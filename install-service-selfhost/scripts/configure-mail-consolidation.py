#!/usr/bin/env python3
"""Merge migrated-service routes into the destination's shared HAProxy config."""
from pathlib import Path
import subprocess
import sys

p = Path('/etc/haproxy/haproxy.cfg')
original = p.read_text()
text = original
lines = text.splitlines(keepends=True)
for index, line in enumerate(lines):
    if line.strip().startswith(('bind *:443 ssl ', 'bind [::]:443 v6only ssl ')):
        for domain in ['cjj365.cc', 'lets-script.com']:
            bundle = Path('/opt/certs') / domain / 'haproxy.pem'
            if bundle.is_file() and str(bundle) not in line:
                line = line.replace(' alpn ', ' crt ' + str(bundle) + ' alpn ')
        lines[index] = line
text = ''.join(lines)
if 'bind [::]:443' not in text:
    ipv4 = next(line for line in lines if line.strip().startswith('bind *:443 ssl '))
    text = text.replace(ipv4, ipv4 + ipv4.replace('bind *:443', 'bind [::]:443 v6only'))
if '# BEGIN cjj365 migrated services' not in text:
    anchor = '    use_backend ipinfo_backend if host_ipinfo'
    assert text.count(anchor) == 1
    block = '''    # BEGIN cjj365 migrated services
    acl host_cjj_mail hdr(host) -i mail.cjj365.cc mail.cjj365.cc:443
    acl host_install_selfhost hdr(host) -i install-selfhost.lets-script.com install-selfhost.lets-script.com:443 install.lets-script.com install.lets-script.com:443 install.cjj365.cc install.cjj365.cc:443
    acl install_dynamic path_beg /install /uninstall /api /health /releases/proxy /assets/cacert.pem
    use_backend cjj365_mail_relay if host_cjj_mail
    use_backend migrated_install_app if host_install_selfhost install_dynamic
    use_backend migrated_install_static if host_install_selfhost
    # END cjj365 migrated services

'''
    text = text.replace(anchor, block + anchor)
    text += '''
# BEGIN cjj365 migrated backends
backend cjj365_mail_relay
    server cjj365_relay 127.0.0.1:18084 check

backend migrated_install_app
    server install_app 127.0.0.1:8787 check

backend migrated_install_static
    server install_static 127.0.0.1:8080 check
# END cjj365 migrated backends
'''
# Upgrade previously installed blocks too, retaining old hostnames until clients
# have migrated. The existing never-lost.app HTTPS certificate serves these names.
installer_hosts = ('install.never-lost.app', 'install-selfhost.never-lost.app')
lines = text.splitlines(keepends=True)
for index, line in enumerate(lines):
    if line.strip().startswith('acl host_install_selfhost hdr(host) -i '):
        names = line.split()
        for host in installer_hosts:
            for name in (host, host + ':443'):
                if name not in names:
                    line = line.rstrip('\n') + ' ' + name + '\n'
        lines[index] = line
text = ''.join(lines)
if text == original:
    print('Migrated HTTP routes already configured.')
    sys.exit(0)
p.write_text(text)
try:
    subprocess.run(['haproxy','-c','-f',str(p)],check=True)
    subprocess.run(['systemctl','reload','haproxy'],check=True)
except BaseException:
    p.write_text(original)
    raise
print('Migrated HTTP routes configured; existing frontend routes preserved.')
