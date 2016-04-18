#!/usr/bin/env python
# coding: utf-8
# vim: set ts=4 sw=4 et:

import ConfigParser
import re
import sys
import threading
import time
import traceback

import formats
from utils import report
from __init__ import __version__

# Try to import psutils
try:
    import psutil
    psutil_available = True
except ImportError:
    psutil_available = False


# Main section name (TODO - move it)
SECT = 'Main'
# Common option prefix
PREFIX = 'metrics-'

# Configuration names
TOKEN = 'token'
INTERVAL = 'interval'
CPU = 'cpu'
VCPU = 'vcpu'
MEM = 'mem'
SWAP = 'swap'
NET = 'net'
DISK = 'disk'
SPACE = 'space'
PROCESS = 'process'


def _psutil_cpu_count():
    """Replaces cpu_count which is missing in older version."""
    try:
        return psutil.NUM_CPUS
    except AttributeError:
        return psutil.cpu_count()

class CpuMetrics(object):

    """Collecting aggregated CPU metrics."""

    def __init__(self, per_core, interval, transport, formatter):
        self._per_core = per_core
        self._interval = interval
        self._transport = transport
        self._formatter = formatter
        self._last = None
        self._vcpus = _psutil_cpu_count()

    @staticmethod
    def construct(curr, last, vcpus, per_core, index=-1):
        user = curr.user - last.user
        nice = curr.nice - last.nice
        system = curr.system - last.system
        idle = curr.idle - last.idle
        iowait = curr.iowait - last.iowait
        irq = curr.irq - last.irq
        softirq = curr.softirq - last.softirq
        try:
            steal = curr.steal - last.steal
            guest = curr.guest - last.guest
            guest_nice = curr.guest_nice - last.guest_nice
        except AttributeError:
            steal = 0
            guest = 0
            guest_nice = 0
        xsum = user + nice + system + idle + iowait + \
            irq + softirq + steal + guest + guest_nice
        if per_core:
            fraction = vcpus / xsum * 100
        else:
            fraction = 1 / xsum * 100
        user *= fraction
        nice *= fraction
        system *= fraction
        idle *= fraction
        iowait *= fraction
        irq *= fraction
        softirq *= fraction
        steal *= fraction
        guest *= fraction
        guest_nice *= fraction
        if index != -1:
            xvcpu = 'vcpu=%d ' % index
        else:
            xvcpu = ''
        return '%suser=%.1f nice=%.1f system=%.1f usage=%.1f idle=%.1f iowait=%.1f irq=%.1f softirq=%.1f steal=%.1f guest=%.1f guest_nice=%.1f vcpus=%d\n' % (
                xvcpu, user, nice, system, user + nice + system + irq + softirq + guest,
                idle, iowait, irq, softirq, steal, guest, guest_nice, vcpus)

    def collect(self):
        curr = psutil.cpu_times()
        if self._last:
            line = CpuMetrics.construct(
                curr, self._last, self._vcpus, self._per_core)
            self._transport.send(self._formatter.format_line(line, msgid='cpu'))
        self._last = curr


class VcpuMetrics(object):

    """Collecting per-CPU metrics."""

    def __init__(self, interval, transport, formatter):
        self._interval = interval
        self._transport = transport
        self._formatter = formatter
        self._vcpus = _psutil_cpu_count()
        self._last = None

    def collect(self):
        try:
            curr = psutil.cpu_times(percpu=True)
        except TypeError:
            return
        last = self._last
        if last:
            for index in range(self._vcpus):
                line = CpuMetrics.construct(
                    curr[index], last[index], self._vcpus, True, index)
                self._transport.send(
                    self._formatter.format_line(line, msgid='vcpu'))
        self._last = curr


class MemMetrics(object):

    """Collecting memory metrics."""

    def __init__(self, interval, transport, formatter):
        self._interval = interval
        self._transport = transport
        self._formatter = formatter

    def collect(self):
        try:
            x = psutil.virtual_memory()
        except AttributeError:
            return
        total = float(x.total)
        line = 'total=%d available=%.1f used=%.1f free=%.1f active=%.1f inactive=%.1f buffers=%.1f cached=%.1f\n' % (
                x.total, x.available / total * 100, x.used / total * 100,
                x.free / total * 100, x.active / total * 100,
                x.inactive / total * 100, x.buffers / total * 100,
                x.cached / total * 100)
        self._transport.send(self._formatter.format_line(line, msgid='mem'))


class SwapMetrics(object):

    """Collection swap metrics."""

    def __init__(self, interval, transport, formatter):
        self._interval = interval
        self._transport = transport
        self._formatter = formatter
        self._last = None

    def _construct(self, curr, last):
        total = float(curr.total)
        sin = curr.sin - last.sin
        sout = curr.sout - last.sout
        if curr.total != 0:
            used = curr.used / total * 100
            free = curr.free / total * 100
        else:
            used = 0
            free = 0
        return 'total=%d used=%.1f free=%.1f in=%d out=%d\n' % (
            curr.total, used, free, sin, sout)

    def collect(self):
        try:
            curr = psutil.swap_memory()
        except AttributeError:
            return
        if self._last:
            line = self._construct(curr, self._last)
            self._transport.send(self._formatter.format_line(line, msgid='swap'))
        self._last = curr


class DiskIoMetrics(object):

    """Collecting disk metrics."""

    def __init__(self, devices, interval, transport, formatter):
        self._parse_devices(devices)
        self._interval = interval
        self._transport = transport
        self._formatter = formatter
        self._last = None
        self._last_sum = None

    def _parse_devices(self, devices):
        xdevices = set(devices.split())
        self._sum = 'sum' in xdevices
        self._all = 'all' in xdevices
        self._devices = frozenset(xdevices - set(['sum', 'all']))

    def _construct(self, device_name, curr, last):
        line = 'device=%s reads=%d writes=%d bytes_read=%d bytes_write=%d time_read=%d time_write=%d\n' % (
                quote(device_name),
                curr.read_count - last.read_count,
                curr.write_count - last.write_count,
                curr.read_bytes - last.read_bytes,
                curr.write_bytes - last.write_bytes,
                curr.read_time - last.read_time,
                curr.write_time - last.write_time)
        self._transport.send(self._formatter.format_line(line, msgid='disk'))

    def collect(self):
        # Collect metrics for all devices
        if self._sum:
            try:
                curr = psutil.disk_io_counters(perdisk=False)
            except:
                # Not enough permissions
                curr = self._last_sum = None
            if self._last_sum:
                self._construct('sum', curr, self._last_sum)
            self._last_sum = curr

        # Collect metrics for each individual device
        if self._all or self._devices:
            try:
                curr_all = psutil.disk_io_counters(perdisk=True)
            except:
                # Typically not enough permissions
                curr_all = self._last = None
            if self._last:
                for curr_device in curr_all:
                    if self._all or curr_device in self._devices:
                        try:
                            curr = curr_all[curr_device]
                            last = self._last[curr_device]
                        except KeyError:
                            continue
                        self._construct(curr_device, curr, last)
            self._last = curr_all


class DiskSpaceMetrics(object):

    """Collecting disk usage metrics."""

    def __init__(self, paths, interval, transport, formatter):
        self._parse_paths(paths)
        self._interval = interval
        self._transport = transport
        self._formatter = formatter

    def _parse_paths(self, paths):
        self._paths = frozenset(paths.split())

    def collect(self):
        for path in self._paths:
            try:
                curr = psutil.disk_usage(path)
                if curr.total != 0:
                    used = curr.used / float(curr.total) * 100
                    free = curr.free / float(curr.total) * 100
                else:
                    used = 0
                    free = 0
                line = 'path=%s size=%d used=%.1f free=%.1f\n' % (
                    quote(path), curr.total, used, free)
                self._transport.send(
                    self._formatter.format_line(line, msgid='space'))
            except:
                # Not enough permissions
                continue


class NetMetrics(object):

    """Collecting network metrics."""

    def __init__(self, nets, interval, transport, formatter):
        self._parse_nets(nets)
        self._interval = interval
        self._transport = transport
        self._formatter = formatter
        self._last = None
        self._last_sum = None

    def _parse_nets(self, nets):
        xnets = set(nets.split())
        self._sum = 'sum' in xnets
        self._select = 'select' in xnets
        self._all = 'all' in xnets
        self._nets = frozenset(xnets - set(['sum', 'select', 'all']))

    def _construct(self, net, curr, last):
        sent_bytes = curr.bytes_sent - last.bytes_sent
        recv_bytes = curr.bytes_recv - last.bytes_recv
        sent_packets = curr.packets_sent - last.packets_sent
        recv_packets = curr.packets_recv - last.packets_recv
        err_in = curr.errin - last.errin
        err_out = curr.errout - last.errout
        drop_in = curr.dropin - last.dropin
        drop_out = curr.dropout - last.dropout
        line = 'net=%s bytes_sent=%d bytes_recv=%d packets_sent=%d packets_recv=%d err_in=%d err_out=%d drop_in=%d drop_out=%d\n' % (
                quote(net), sent_bytes, recv_bytes, sent_packets,
                recv_packets, err_in, err_out, drop_in, drop_out)
        self._transport.send(self._formatter.format_line(line, msgid='net'))

    @staticmethod
    def _selected(net):
        for x in ['eth', 'en', 'ww', 'wl', 'venet', 'veth']:
            if net.startswith(x):
                return True
        return False

    def collect(self):
        # Summary of all interfaces
        if self._sum:
            counters = psutil.net_io_counters(pernic=False)
            if self._last_sum:
                self._construct('sum', counters, self._last_sum)
            self._last_sum = counters

        # Per-interface metrics
        if self._all or self._select or self._nets:
            counters = psutil.net_io_counters(pernic=True)
            if self._last:
                for net in counters:
                    if self._all or net in self._nets or (self._select and self._selected(net)):
                        try:
                            self._construct(
                                net, counters[net], self._last[net])
                        except:
                            pass  # Typically not enough permissions
            self._last = counters


class ProcMetrics(object):

    """Collecting process metrics."""

    def __init__(self, name, pattern, token, interval, transport, formatter):
        self._name = name
        self._pattern = pattern
        self._token = token
        self._interval = interval
        self._transport = transport
        self._formatter = formatter
        self._proc = None
        self._last_cpu = None
        self._last_io = None
        try:
            self._total = psutil.virtual_memory().total
        except AttributeError:
            self._total = 0

    def _find_proc(self):
        for proc in psutil.process_iter():
            cmdline = ' '.join(proc.cmdline())
            if cmdline and cmdline.find(self._pattern) != -1:
                return proc

    def _get_io_counters(self):
        try:
            return self._proc.io_counters()
        except:
            return None

    def _get_fds(self):
        try:
            return self._proc.num_fds()
        except:
            return None

    def collect(self):
        if not self._total:
            return
        if self._proc and not self._proc.is_running():
            self._proc = None
        if not self._proc:
            self._proc = self._find_proc()
        if not self._proc:
            return

        proc = self._proc
        cpu = proc.cpu_times()
        mem = proc.memory_info()
        io = self._get_io_counters()
        fds = self._get_fds()

        if self._last_cpu:
            if io and self._last_io:
                lio = self._last_io
                io_line = ' reads=%d writes=%d bytes_read=%d bytes_write=%d' % (
                        io.read_count - lio.read_count,
                        io.write_count - lio.write_count,
                        io.read_bytes - lio.read_bytes,
                        io.write_bytes - lio.write_bytes)
            else:
                io_line = ''

            if fds:
                fds_line = ' fds=%d' % fds
            else:
                fds_line = ''

            lcpu = self._last_cpu
            cpu_user = float(cpu.user - lcpu.user) / self._interval * 100
            cpu_system = float(cpu.system - lcpu.system) / self._interval * 100
            line = 'cpu_user=%.1f cpu_system=%.1f%s%s mem=%.1f total=%d rss=%d vms=%d\n' % (
                    cpu_user, cpu_system,
                    io_line, fds_line,
                    proc.memory_percent(), self._total, mem.rss, mem.vms)
            self._transport.send(
                self._formatter.format_line(line, msgid=self._name, token=self._token))
        self._last_cpu = cpu
        self._last_io = io


class Metrics(object):

    """Metrics collecting class."""

    def __init__(self, conf, default_transport, formatter, debug):
        """Creates an instance of metrics from the configuration."""
        self._ready = False
        if not psutil_available:
            if debug:
                report("Warning: Cannot instantiate metrics, psutil library is not available.")
            return
        if not conf.token:
            if debug:
                report("Warning: Cannot instantiate metrics, token not specified.")
            return

        if debug and not default_transport:
            self._transport = StderrTransport(None)
        elif debug:
            self._transport = StderrTransport(default_transport.get())
        else:
            self._transport = default_transport.get()
        self._formatter = formatter
        self._debug = debug

        self._timer = None
        self._shutdown = False
        self._interval = self._parse_interval(conf.interval)
        if self._interval == 0:
            report("Warning: Cannot instantiate metrics, invalid interval `%s'." % conf.interval)

        self._items = self._instantiate(conf)
        self._ready = True

    def _parse_interval(self, interval):
        if len(interval) == 0:
            return 5  # Default is 5 second interval
        unit = interval[-1:]
        try:
            value = int(interval[:-1])
        except ValueError:
            return 0
        if unit == 's':
            pass
        elif unit == 'm':
            value *= 60
        else:
            return 0
        return value

    def _instantiate(self, conf):
        items = []
        if conf.cpu:
            if conf.cpu in ['core', 'system']:
                items.append( CpuMetrics(conf.cpu == 'core', self._interval, self._transport, self._formatter))
            else:
                report("Unrecognized cpu option `%s', `core' or `system' expected" % conf.cpu)
        if conf.vcpu:
            if conf.vcpu == 'core':
                items.append( VcpuMetrics(self._interval, self._transport, self._formatter))
            else:
                report("Unrecognized vcpu option `%s', `core' expected" % conf.vcpu)
        if conf.mem:
            if conf.mem == 'system':
                items.append( MemMetrics(self._interval, self._transport, self._formatter))
            else:
                report("Unrecognized mem option `%s', `system' expected" % conf.mem)
        if conf.swap:
            if conf.swap == 'system':
                items.append(SwapMetrics(self._interval, self._transport, self._formatter))
            else:
                report("Unrecognized swap option `%s', `system' expected" % conf.swap)
        if conf.disk:
            items.append(DiskIoMetrics(conf.disk, self._interval, self._transport, self._formatter))
        if conf.space:
            items.append(DiskSpaceMetrics(conf.space, self._interval, self._transport, self._formatter))
        if conf.net:
            items.append(NetMetrics(conf.net, self._interval, self._transport, self._formatter))

        for process in conf.processes:
            items.append(ProcMetrics(process[0], process[1], process[2], self._interval, self._transport, self._formatter))

        return items

    def _schedule(self, ethalon):
        # TODO - align metrics on time boundary
        ethalon += self._interval
        next_step = (ethalon - time.time()) % self._interval
        if not self._shutdown:
            self._timer = threading.Timer(next_step, self._collect_metrics, ())
            self._timer.daemon = True
            self._timer.start()

    def _collect_metrics(self):
        ethalon = time.time()

        for x in self._items:
            try:
                x.collect()
            except Exception, e:
                # Make sure we don't propagate any unexpected exceptions
                # Typically `permission denied' on hard-ended systems
                if self._debug:
                    report("Warning: `%s'" % e)
                    report(''.join(traceback.format_tb(sys.exc_info()[2])))

        self._schedule(ethalon)

    def _collect_info(self):
        line = "agent_version=%s\n" % __version__
        self._transport.send(
                self._formatter.format_line(line, msgid='start'))

    def start(self):
        if self._ready:
            self._schedule(time.time())
            self._collect_info()

    def cancel(self):
        if self._ready:
            self._shutdown = True
            t = self._timer
            if t:
                t.cancel()


class StderrTransport(object):

    """Default transport encapsulation with additional logging to stderr."""

    def __init__(self, transport=None):
        self._transport = transport

    def get(self):
        return self

    def send(self, entry):
        print >> sys.stderr, entry,
        if self._transport:
            self._transport.send(entry)


class MetricsConfig(object):

    """Metrics configuration holder."""

    DEFAULTS = {
        TOKEN: '',
        INTERVAL: '5s',
        CPU: 'system',
        VCPU: '',
        MEM: 'system',
        SWAP: 'system',
        NET: 'sum',
        DISK: 'sum',
        SPACE: '/',
    }

    def __init__(self):
        # Set instance fields initialized to default values
        self.token = '' # Avoid pylint error
        for item in self.DEFAULTS:
            self.__dict__[item] = self.DEFAULTS[item]
        self.processes = []

    def load(self, conf):
        """Loads metrics configuration."""
        # Basic metrics
        for item in self.DEFAULTS:
            try:
                self.__dict__[item] = conf.get(SECT, PREFIX + item)
            except ConfigParser.NoOptionError:
                pass
        # Process metrics
        for section in conf.sections():
            if section != SECT:
                try:
                    try:
                        token = conf.get(section, PREFIX + TOKEN)
                    except ConfigParser.NoOptionError:
                        token = ''
                    pattern = conf.get(section, PREFIX + PROCESS)
                    self.processes.append([section, pattern, token])
                except ConfigParser.NoOptionError:
                    pass

    def save(self, conf):
        """Saves all metrics conficuration."""
        # Basic metrics
        for item in self.DEFAULTS:
            conf.set(SECT, PREFIX + item, self.__dict__[item])
        # Process metrics
        for process in self.processes:
            try:
                conf.add_section(process[0])
            except ConfigParser.DuplicateSectionError:
                continue
            conf.set(process[0], PREFIX + PROCESS, process[1])
            if process[2]:
                conf.set(process[0], PREFIX + TOKEN, process[2])

# Pattern matching safe values, values that does not need to be quited
SAFE_CHARS = re.compile(r'^[a-zA-Z0-9_]*$')


def quote(x):
    """Encloses the string with quotes if needed. It does not escape
    characters."""
    if SAFE_CHARS.match(x):
        return x
    else:
        return '"%s"' % x

if __name__ == '__main__':
    metrics = None
    try:
        conf = MetricsConfig()
        conf.__dict__[VCPU] = 'core'
        conf.__dict__[NET] = 'sum all'
        conf.__dict__[DISK] = 'sum all'
        conf.__dict__[TOKEN] = 'e2b405df-858b-4148-92a5-37d06dbd50f5'
        metrics = Metrics(conf, None,
                formats.FormatSyslog('', 'le', ''), True)
        metrics.start()
        time.sleep(600)  # Is there a better way?
    except KeyboardInterrupt:
        print >>sys.stderr, "\nTerminated"

    if metrics:
        metrics.cancel()
