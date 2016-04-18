
# coding: utf-8
# vim: set ts=4 sw=4 et:

import errno
import httplib
import os
import re
import socket
import sys
try:
    import uuid
    FEAT_UUID = True
except ImportError:
    FEAT_UUID = False
from backports import match_hostname, CertificateError

import logging


__author__ = 'Logentries'

__all__ = ["EXIT_OK", "EXIT_NO", "EXIT_HELP", "EXIT_ERR", "EXIT_TERMINATED",
           "ServerHTTPSConnection", "LOG_LE_AGENT", "create_conf_dir",
           "default_cert_file", "system_cert_file", "domain_connect",
           "no_more_args", "find_hosts", "find_logs", "find_api_obj_by_key", "find_api_obj_by_name", "die",
           "rfile", 'TCP_TIMEOUT', "rm_pidfile", "set_proc_title", "uuid_parse", "report"]

# Return codes
EXIT_OK = 0
EXIT_NO = 1
EXIT_ERR = 3
EXIT_HELP = 4
EXIT_TERMINATED = 5  # Terminated by user (Ctrl+C)

LE_CERT_NAME = 'ca-certs.pem'

TCP_TIMEOUT = 10  # TCP timeout for the socket in seconds


authority_certificate_files = [  # Debian 5.x, 6.x, 7.x, Ubuntu 9.10, 10.4, 13.0
                                 "/etc/ssl/certs/ca-certificates.crt",
                                 # Fedora 12, Fedora 13, CentOS 5
                                 "/usr/share/purple/ca-certs/GeoTrust_Global_CA.pem",
                                 # Amazon AMI, CentOS 7, recent RHs
                                 "/etc/pki/tls/certs/ca-bundle.crt",
                                 # FreeBSD 10.2
                                 "/etc/ssl/cert.pem",
]

LOG_LE_AGENT = 'logentries.com'

log = logging.getLogger(LOG_LE_AGENT)

try:
    import ssl

    wrap_socket = ssl.wrap_socket
    FEAT_SSL = True
    try:
        ssl.create_default_context
        FEAT_SSL_CONTEXT = True
    except AttributeError:
        FEAT_SSL_CONTEXT = False
except ImportError:
    FEAT_SSL = False
    FEAT_SSL_CONTEXT = False

    def wrap_socket(sock, ca_certs=None, cert_reqs=None):
        return socket.ssl(sock)

def report(what):
    print >> sys.stderr, what

class ServerHTTPSConnection(httplib.HTTPSConnection):

    """
    A slight modification of HTTPSConnection to verify the certificate
    """

    def __init__(self, config, server, port, cert_file):
        self.no_ssl = config.suppress_ssl or not FEAT_SSL
        if self.no_ssl:
            if config.use_proxy == True:
                httplib.HTTPSConnection.__init__(self, config.proxy_url, config.proxy_port, context=context)
                if hasattr(httplib.HTTPSConnection, "set_tunnel"):
                    httplib.HTTPSConnection.set_tunnel(self, server, port)
                else:
                    httplib.HTTPSConnection._set_tunnel(self, server, port)
            else:
                httplib.HTTPSConnection.__init__(self, server, port)
        else:
            self.cert_file = cert_file
            if FEAT_SSL_CONTEXT:
                context = ssl.create_default_context(cafile=cert_file)
                if config.use_proxy == True:
                    httplib.HTTPSConnection.__init__(self, config.proxy_url, config.proxy_port, context=context)
                    if hasattr(httplib.HTTPSConnection, "set_tunnel"):
                        httplib.HTTPSConnection.set_tunnel(self, server, port)
                    else:
                        httplib.HTTPSConnection._set_tunnel(self, server, port)
                else:
                    httplib.HTTPSConnection.__init__(self, server, port, context=context)
            else:
                if config.use_proxy == True:
                    httplib.HTTPSConnection.__init__(self, config.proxy_url, config.proxy_port, cert_file=cert_file)
                    if hasattr(httplib.HTTPSConnection, "set_tunnel"):
                        httplib.HTTPSConnection.set_tunnel(self, server, port)
                    else:
                        httplib.HTTPSConnection._set_tunnel(self, server, port)
                else:
                    httplib.HTTPSConnection.__init__(self, server, port, cert_file=cert_file)

    def connect(self):
        if FEAT_SSL_CONTEXT:
            httplib.HTTPSConnection.connect(self)
        else:
            if self.no_ssl:
                return httplib.HTTPSConnection.connect(self)
            sock = create_connection(self.host, self.port)
            try:
                if self._tunnel_host:
                    self.sock = sock
                    self._tunnel()
            except AttributeError:
                pass
            self.sock = wrap_socket(
                sock, ca_certs=self.cert_file, cert_reqs=ssl.CERT_REQUIRED)
            try:
                match_hostname(self.sock.getpeercert(), self.host)
            except CertificateError, ce:
                die("Could not validate SSL certificate for %s: %s" % (
                    self.host, ce.message))


def default_cert_file_name(config):
    """
    Construct full file name to the default certificate file.
    """
    return config.config_dir_name + LE_CERT_NAME


def create_conf_dir(config):
    """
    Creates directory for the configuration file.
    """
    # Create logentries config
    try:
        os.makedirs(config.config_dir_name)
    except OSError, e:
        if e.errno != errno.EEXIST:
            if e.errno == errno.EACCES:
                die("You don't have permission to create logentries config file. Please run logentries agent as root.")
            die('Error: %s' % e)


def write_default_cert_file(config, authority_certificate):
    """
    Writes default certificate file in the configuration directory.
    """
    create_conf_dir(config)
    cert_filename = default_cert_file_name(config)
    f = open(cert_filename, 'wb')
    f.write(authority_certificate)
    f.close()


def default_cert_file(config):
    """
    Returns location of the default certificate file or None. It tries to write the
    certificate file if it is not there or it is outdated.
    """
    cert_filename = default_cert_file_name(config)
    try:
        # If the certificate file is not there, create it
        if not os.path.exists(cert_filename):
            write_default_cert_file(config, authority_certificate)
            return cert_filename

        # If it is there, check if it is outdated
        curr_cert = rfile(cert_filename)
        if curr_cert != authority_certificate:
            write_default_cert_file(config, authority_certificate)
    except IOError:
        # Cannot read/write certificate file, ignore
        return None
    return cert_filename


def system_cert_file():
    """
    Finds the location of our lovely site's certificate on the system or None.
    """
    for f in authority_certificate_files:
        if os.path.exists(f):
            return f
    return None


def create_connection(host, port):
    """
    A simplified version of socket.create_connection from Python 2.6.
    """
    for addr_info in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
        af, stype, proto, cn, sa = addr_info
        soc = None
        try:
            soc = socket.socket(af, stype, proto)
            soc.settimeout(TCP_TIMEOUT)
            soc.connect(sa)
            return soc
        except socket.error:
            if socket:
                soc.close()

    raise socket.error, "Cannot make connection to %s:%s" % (host, port)


def make_https_connection(config, s, port):
    """
    Makes HTTPS connection. Tried all available certificates.
    """
    if not config.use_ca_provided:
        # Try to connect with system certificate
        try:
            cert_file = system_cert_file()
            if cert_file:
                return ServerHTTPSConnection(config, s, port, cert_file)
        except socket.error, e:
            pass

    # Try to connect with our default certificate
    cert_file = default_cert_file(config)
    if not cert_file:
        die('Error: Cannot find suitable CA certificate.')
    return ServerHTTPSConnection(config, s, port, cert_file)


def domain_connect(config, domain, Domain):
    """
    Connects to the domain specified.
    """
    # Find the correct server address
    s = domain
    if Domain == Domain.API:
        if config.force_domain:
            s = config.force_domain
        elif config.force_api_host:
            s = config.force_api_host
        else:
            s = Domain.API

    # Special case for local debugging
    if config.debug_local:
        if s == Domain.API:
            s = Domain.API_LOCAL
        else:
            s = Domain.MAIN_LOCAL

    # Determine if to use SSL for connection
    # Never use SSL for debugging, always use SSL with main server
    use_ssl = True
    if config.debug_local:
        use_ssl = False
    elif s == Domain.API:
        use_ssl = not config.suppress_ssl

    # Connect to server with SSL in untrusted network
    if use_ssl:
        port = 443
    else:
        port = 80
    if config.debug_local:
        if s == Domain.API:
            port = 8000
        else:
            port = 8081
    log.debug('Connecting to %s:%s', s, port)

    # Pass the connection
    if use_ssl:
        return make_https_connection(config, s, port)
    else:
        if config.use_proxy == True:
            conn = httplib.HTTPConnection(config.proxy_url, config.proxy_port)
            if hasattr(httplib.HTTPConnection, "set_tunnel"):
                conn.set_tunnel(s, port)
            else:
                conn._set_tunnel(s, port)
            return conn
        else:
            return httplib.HTTPConnection(s, port)



def no_more_args(args):
    """
    Exits if there are any arguments given.
    """
    if len(args) != 0:
        die("No more than one argument is expected.")


def expr_match(expr, text):
    """
    Returns True if the text matches with expression. If the expression
    starts with / it is a regular expression.
    """
    if expr[0] == '/':
        if re.match(expr[1:], text):
            return True
    else:
        if expr[0:2] == '\\/':
            return text == expr[1:]
        else:
            return text == expr
    return False


def find_hosts(expr, hosts):
    """
    Finds host name among hosts.
    """
    result = []
    for host in hosts:
        if uuid_match(expr, host['key']) or expr_match(expr, host['name']) or expr_match(expr, host['hostname']):
            result.append(host)
    return result


def log_match(expr, log_item):
    """
    Returns true if the expression given matches the log. Expression is either
    a simple word or a regular expression if it starts with '/'.

    We perform the test on UUID, log name, and file name.
    """
    return uuid_match(
        expr, log_item['key']) or expr_match(expr, log_item['name']) or expr_match(expr,
                                                                                   log_item['filename'])


def find_logs(expr, hosts):
    """
    Finds log name among hosts. The searching expresion have to parts: host
    name and logs name. Both parts are divided by :.
    """
    # Decode expression
    l = expr.find(':')
    if l != -1:
        host_expr = expr[0:l]
        log_expr = expr[l + 1:]
    else:
        host_expr = '/.*'
        log_expr = expr

    adepts = find_hosts(host_expr, hosts)
    logs = []
    for host in adepts:
        for xlog in host['logs']:
            if log_match(log_expr, xlog):
                logs.append(xlog)
    return logs


def find_api_obj_by_name(obj_list, name):
    """
    Finds object in a list by its name parameter. List of objects must conform
    to that of a log or host entity from api.
    """
    result = None
    for obj in obj_list:
        if obj['name'] == name:
            result = obj
            break
    return result


def find_api_obj_by_key(obj_list, key):
    """
    Finds object in a list by its key parameter. List of objects must conform
    to that of a log or host entity from api.
    """
    result = None
    for obj in obj_list:
        if obj['key'] == key:
            result = obj
            break
    return result


def die(cause, exit_code=EXIT_ERR):
    log.critical(cause)
    sys.exit(exit_code)


def rfile(name):
    """
    Returns content of the file, without trailing newline.
    """
    x = open(name).read()
    if len(x) != 0 and x[-1] == '\n':
        x = x[0:len(x) - 1]
    return x


def rm_pidfile(config):
    """
    Removes PID file. Called when the agent exits.
    """
    try:
        if config.pid_file:
            os.remove(config.pid_file)
    except OSError:
        pass


def set_proc_title(title):
    try:
        import setproctitle
        setproctitle.setproctitle(title)
    except ImportError:
        pass


def uuid_match(uuid, text):
    """
    Returns True if the uuid given is uuid and it matches to the text.
    """
    return is_uuid(uuid) and uuid == text


def is_uuid(x):
    """
    Returns true if the string given appears to be UUID.
    """
    return re.match(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', x)


def uuid_parse(text):
    """Returns uuid given or None in case of syntax error.
    """
    try:
        if FEAT_UUID:
            return uuid.UUID(text).__str__()
        else:
            low_text = text.lower()
            if re.match( r'^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}', low_text):
                return low_text
    except ValueError:
        pass
    return None


#
# Authority certificate
#
# Used if not provided by the underlying system

#
# *.logentries.com
#   Fingerprint SHA1: 777167a0547348cd88b764e68a275e587b2ac15a
# GeoTrust SSL CA - G4 (provided by the server)
#   Fingerprint SHA1: ac8f7c5bc86ef1896f2d161c32a57aab37d364da
# GeoTrust Global CA
#   Fingerprint SHA1: de28f4a4ffe5b92fa3c503d1a349a7f9962a8212

# api.logentries.com
#   Fingerprint SHA1: 48dc8a4533a636b22973f7b60c10c1e522093b68
# GeoTrust DV SSL CA - G4 (provided by the server)
#   Fingerprint SHA1: 35e540f4d36e94d9005b18dce27ca2ae8ca0020d
# GeoTrust Global CA
#   Fingerprint SHA1: de28f4a4ffe5b92fa3c503d1a349a7f9962a8212

# data.logentries.com (1)
#   Fingerprint SHA1: 9d54010acd58cb7e16a872551c348c94ae9014e4
# COMODO RSA Domain Validation Secure Server CA (provided by the server)
#   Fingerprint SHA1: 339cdd57cfd5b141169b615ff31428782d1da639
# COMODO RSA Certification Authority
#   Fingerprint SHA1: afe5d244a8d1194230ff479fe2f897bbcd7a8cb4

# data.logentries.com (2)
#   Fingerprint SHA1: 9d54010acd58cb7e16a872551c348c94ae9014e4
# COMODO RSA Domain Validation Secure Server CA  (provided by the server)
#   Fingerprint SHA1: 339cdd57cfd5b141169b615ff31428782d1da639
# COMODO RSA Certification Authority  (provided by the server)
#   Fingerprint SHA1: f5ad0bcc1ad56cd150725b1c866c30ad92ef21b0
# AddTrust External CA Root
#   Fingerprint SHA1: 02faf3e291435468607857694df5e45b68851868


authority_certificate = ""


# GeoTrust Global CA
# Root CA for *.logentries.com and api.logentries.com
# SHA1 DE:28:F4:A4:FF:E5:B9:2F:A3:C5:03:D1:A3:49:A7:F9:96:2A:82:12
authority_certificate += """-----BEGIN CERTIFICATE-----
MIIDVDCCAjygAwIBAgIDAjRWMA0GCSqGSIb3DQEBBQUAMEIxCzAJBgNVBAYTAlVT
MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i
YWwgQ0EwHhcNMDIwNTIxMDQwMDAwWhcNMjIwNTIxMDQwMDAwWjBCMQswCQYDVQQG
EwJVUzEWMBQGA1UEChMNR2VvVHJ1c3QgSW5jLjEbMBkGA1UEAxMSR2VvVHJ1c3Qg
R2xvYmFsIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2swYYzD9
9BcjGlZ+W988bDjkcbd4kdS8odhM+KhDtgPpTSEHCIjaWC9mOSm9BXiLnTjoBbdq
fnGk5sRgprDvgOSJKA+eJdbtg/OtppHHmMlCGDUUna2YRpIuT8rxh0PBFpVXLVDv
iS2Aelet8u5fa9IAjbkU+BQVNdnARqN7csiRv8lVK83Qlz6cJmTM386DGXHKTubU
1XupGc1V3sjs0l44U+VcT4wt/lAjNvxm5suOpDkZALeVAjmRCw7+OC7RHQWa9k0+
bw8HHa8sHo9gOeL6NlMTOdReJivbPagUvTLrGAMoUgRx5aszPeE4uwc2hGKceeoW
MPRfwCvocWvk+QIDAQABo1MwUTAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTA
ephojYn7qwVkDBF9qn1luMrMTjAfBgNVHSMEGDAWgBTAephojYn7qwVkDBF9qn1l
uMrMTjANBgkqhkiG9w0BAQUFAAOCAQEANeMpauUvXVSOKVCUn5kaFOSPeCpilKIn
Z57QzxpeR+nBsqTP3UEaBU6bS+5Kb1VSsyShNwrrZHYqLizz/Tt1kL/6cdjHPTfS
tQWVYrmm3ok9Nns4d0iXrKYgjy6myQzCsplFAMfOEVEiIuCl6rYVSAlk6l5PdPcF
PseKUgzbFbS9bZvlxrFUaKnjaZC2mqUPuLk/IH2uSrW4nOQdtqvmlKXBx4Ot2/Un
hw4EbNX/3aBd7YdStysVAq45pmp06drE57xNNB6pXE0zX5IJL4hmXXeXxx12E6nV
5fEWCRE11azbJHFwLJhWC9kXtNHjUStedejV0NxPNO3CBWaAocvmMw==
-----END CERTIFICATE-----
"""

# COMODO RSA Certification Authority
# Root CA for data.logentries.com (1)
# SHA1 AF:E5:D2:44:A8:D1:19:42:30:FF:47:9F:E2:F8:97:BB:CD:7A:8C:B4
authority_certificate += """-----BEGIN CERTIFICATE-----
MIIF2DCCA8CgAwIBAgIQTKr5yttjb+Af907YWwOGnTANBgkqhkiG9w0BAQwFADCB
hTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
A1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxKzApBgNV
BAMTIkNPTU9ETyBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTAwMTE5
MDAwMDAwWhcNMzgwMTE4MjM1OTU5WjCBhTELMAkGA1UEBhMCR0IxGzAZBgNVBAgT
EkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMR
Q09NT0RPIENBIExpbWl0ZWQxKzApBgNVBAMTIkNPTU9ETyBSU0EgQ2VydGlmaWNh
dGlvbiBBdXRob3JpdHkwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCR
6FSS0gpWsawNJN3Fz0RndJkrN6N9I3AAcbxT38T6KhKPS38QVr2fcHK3YX/JSw8X
pz3jsARh7v8Rl8f0hj4K+j5c+ZPmNHrZFGvnnLOFoIJ6dq9xkNfs/Q36nGz637CC
9BR++b7Epi9Pf5l/tfxnQ3K9DADWietrLNPtj5gcFKt+5eNu/Nio5JIk2kNrYrhV
/erBvGy2i/MOjZrkm2xpmfh4SDBF1a3hDTxFYPwyllEnvGfDyi62a+pGx8cgoLEf
Zd5ICLqkTqnyg0Y3hOvozIFIQ2dOciqbXL1MGyiKXCJ7tKuY2e7gUYPDCUZObT6Z
+pUX2nwzV0E8jVHtC7ZcryxjGt9XyD+86V3Em69FmeKjWiS0uqlWPc9vqv9JWL7w
qP/0uK3pN/u6uPQLOvnoQ0IeidiEyxPx2bvhiWC4jChWrBQdnArncevPDt09qZah
SL0896+1DSJMwBGB7FY79tOi4lu3sgQiUpWAk2nojkxl8ZEDLXB0AuqLZxUpaVIC
u9ffUGpVRr+goyhhf3DQw6KqLCGqR84onAZFdr+CGCe01a60y1Dma/RMhnEw6abf
Fobg2P9A3fvQQoh/ozM6LlweQRGBY84YcWsr7KaKtzFcOmpH4MN5WdYgGq/yapiq
crxXStJLnbsQ/LBMQeXtHT1eKJ2czL+zUdqnR+WEUwIDAQABo0IwQDAdBgNVHQ4E
FgQUu69+Aj36pvE8hI6t7jiY7NkyMtQwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB
/wQFMAMBAf8wDQYJKoZIhvcNAQEMBQADggIBAArx1UaEt65Ru2yyTUEUAJNMnMvl
wFTPoCWOAvn9sKIN9SCYPBMtrFaisNZ+EZLpLrqeLppysb0ZRGxhNaKatBYSaVqM
4dc+pBroLwP0rmEdEBsqpIt6xf4FpuHA1sj+nq6PK7o9mfjYcwlYRm6mnPTXJ9OV
2jeDchzTc+CiR5kDOF3VSXkAKRzH7JsgHAckaVd4sjn8OoSgtZx8jb8uk2Intzna
FxiuvTwJaP+EmzzV1gsD41eeFPfR60/IvYcjt7ZJQ3mFXLrrkguhxuhoqEwWsRqZ
CuhTLJK7oQkYdQxlqHvLI7cawiiFwxv/0Cti76R7CZGYZ4wUAc1oBmpjIXUDgIiK
boHGhfKppC3n9KUkEEeDys30jXlYsQab5xoq2Z0B15R97QNKyvDb6KkBPvVWmcke
jkk9u+UJueBPSZI9FoJAzMxZxuY67RIuaTxslbH9qh17f4a+Hg4yRvv7E491f0yL
S0Zj/gA0QHDBw7mh3aZw4gSzQbzpgJHqZJx64SIDqZxubw5lT2yHh17zbqD5daWb
QOhTsiedSrnAdyGN/4fy3ryM7xfft0kL0fJuMAsaDk527RH89elWsn2/x20Kk4yl
0MC2Hb46TpSi125sC8KKfPog88Tk5c0NqMuRkrF8hey1FGlmDoLnzc7ILaZRfyHB
NVOFBkpdn627G190
-----END CERTIFICATE-----
"""

# AddTrust External CA Root
# Root CA for data.logentries.com (2)
# SHA1 02:FA:F3:E2:91:43:54:68:60:78:57:69:4D:F5:E4:5B:68:85:18:68
authority_certificate += """-----BEGIN CERTIFICATE-----
MIIENjCCAx6gAwIBAgIBATANBgkqhkiG9w0BAQUFADBvMQswCQYDVQQGEwJTRTEU
MBIGA1UEChMLQWRkVHJ1c3QgQUIxJjAkBgNVBAsTHUFkZFRydXN0IEV4dGVybmFs
IFRUUCBOZXR3b3JrMSIwIAYDVQQDExlBZGRUcnVzdCBFeHRlcm5hbCBDQSBSb290
MB4XDTAwMDUzMDEwNDgzOFoXDTIwMDUzMDEwNDgzOFowbzELMAkGA1UEBhMCU0Ux
FDASBgNVBAoTC0FkZFRydXN0IEFCMSYwJAYDVQQLEx1BZGRUcnVzdCBFeHRlcm5h
bCBUVFAgTmV0d29yazEiMCAGA1UEAxMZQWRkVHJ1c3QgRXh0ZXJuYWwgQ0EgUm9v
dDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALf3GjPm8gAELTngTlvt
H7xsD821+iO2zt6bETOXpClMfZOfvUq8k+0DGuOPz+VtUFrWlymUWoCwSXrbLpX9
uMq/NzgtHj6RQa1wVsfwTz/oMp50ysiQVOnGXw94nZpAPA6sYapeFI+eh6FqUNzX
mk6vBbOmcZSccbNQYArHE504B4YCqOmoaSYYkKtMsE8jqzpPhNjfzp/haW+710LX
a0Tkx63ubUFfclpxCDezeWWkWaCUN/cALw3CknLa0Dhy2xSoRcRdKn23tNbE7qzN
E0S3ySvdQwAl+mG5aWpYIxG3pzOPVnVZ9c0p10a3CitlttNCbxWyuHv77+ldU9U0
WicCAwEAAaOB3DCB2TAdBgNVHQ4EFgQUrb2YejS0Jvf6xCZU7wO94CTLVBowCwYD
VR0PBAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wgZkGA1UdIwSBkTCBjoAUrb2YejS0
Jvf6xCZU7wO94CTLVBqhc6RxMG8xCzAJBgNVBAYTAlNFMRQwEgYDVQQKEwtBZGRU
cnVzdCBBQjEmMCQGA1UECxMdQWRkVHJ1c3QgRXh0ZXJuYWwgVFRQIE5ldHdvcmsx
IjAgBgNVBAMTGUFkZFRydXN0IEV4dGVybmFsIENBIFJvb3SCAQEwDQYJKoZIhvcN
AQEFBQADggEBALCb4IUlwtYj4g+WBpKdQZic2YR5gdkeWxQHIzZlj7DYd7usQWxH
YINRsPkyPef89iYTx4AWpb9a/IfPeHmJIZriTAcKhjW88t5RxNKWt9x+Tu5w/Rw5
6wwCURQtjr0W4MHfRnXnJK3s9EK0hZNwEGe6nQY1ShjTK3rMUUKhemPR5ruhxSvC
Nr4TDea9Y355e6cJDUCrat2PisP29owaQgVR1EX1n6diIWgVIEM8med8vSTYqZEX
c4g/VhsxOBi0cQ+azcgOno4uG+GMmIPLHzHxREzGBHNJdmAPx/i9F4BrLunMTA5a
mnkPIAou1Z5jJh5VkpTYghdae9C8x49OhgQ=
-----END CERTIFICATE-----
"""
