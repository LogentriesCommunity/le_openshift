
# coding: utf-8
# vim: set ts=4 sw=4 et:

__author__ = 'Logentries'

__all__ = ['FormatPlain', 'FormatSyslog', 'get_formatter']


import datetime
import socket
import string


class FormatPlain(object):
    """Formats lines as plain text, prepends each line with token."""

    def __init__(self, token):
        self._token = token

    def format_line(self, line):
        return self._token + line


class FormatSyslog(object):
    """Formats lines according to Syslog format RFC 5424. Hostname is taken
    from configuration or current hostname is used."""

    def __init__(self, hostname, appname, token):
        if hostname:
            self._hostname = _sanitize_syslog_name(hostname)
        else:
            self._hostname = _sanitize_syslog_name(socket.gethostname())
        self._appname = _sanitize_syslog_name(appname)
        self._token = token

    def format_line(self, line, msgid='-', token=None):
        if not token:
            token = self._token
        return '%s<14>1 %sZ %s %s - %s - %s'%(
            token, datetime.datetime.utcnow().isoformat('T'),
            self._hostname, self._appname,
            msgid, line)


class FormatCustom(object):
    """Formats lines based of pattern given."""

    def __init__(self, pattern, hostname, appname, token):
        if hostname:
            self._hostname = _sanitize_syslog_name(hostname)
        else:
            self._hostname = _sanitize_syslog_name(socket.gethostname())
        self._appname = _sanitize_syslog_name(appname)
        self._token = token
        self._pattern = pattern.decode('utf8', 'ignore')
        self._template = string.Template(token + self._pattern)

    def format_line(self, line):
        # Convert the pattern into output string
        # this is performance sub-optimal
        return self._template.substitute({
            'isodatetime': datetime.datetime.utcnow().isoformat('T'),
            'hostname': self._hostname,
            'appname': self._appname,
            'line': line
            })

def get_formatter(definition, hostname, log_name, log_token):
    """Instantiates formatter defined by its name or pattern.
    """
    # Check for known formatters
    if definition == 'plain':
        return FormatPlain(log_token).format_line
    elif definition == 'syslog':
        return FormatSyslog(hostname, log_name, log_token).format_line

    # Check for general pattern
    if definition and definition.find('$line') >= 0:
        return FormatCustom(definition, hostname, log_name, log_token).format_line

    # Formatter not found
    return None

def _sanitize_syslog_name(original):
    """Replaces invalid characters from syslog name entry.
    """
    return original.decode('utf8', 'ignore').replace(' ', '_')

