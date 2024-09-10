def sort_pubkey(key):
    try:
        return key.split(' ')[2]
    except IndexError:
        return key

if node.os in node.OS_FAMILY_DEBIAN:
    pkg_apt = {
        "openssh-server": {
            'tags': ['pkg_openssh-server'],
        },
    }
elif node.os in node.OS_FAMILY_REDHAT or node.os == 'amazonlinux':
    pkg_yum = {
        'openssh-server': {
            'tags': ['pkg_openssh-server'],
        }
    }

svc_systemd = {
    'ssh': {
        'enabled': True,
        'running': True,
    }
}

sign_host_keys = {}
if node.metadata.get('openssh').get('sign_host_keys').get('enabled'):
    conf = node.metadata.get('openssh').get('sign_host_keys')

    for key_format in conf.get('formats'):
        sign_host_keys[f'/etc/ssh/ssh_host_{key_format}_key'] = {
            'ca_password': conf.get('ca_password'),
            'ca_path': conf.get('ca_path'),
            'days_valid': conf.get('days_valid'),
            'renew_days': conf.get('renew_days'),
            'triggers': [
                'svc_systemd:ssh:restart',
            ]
        }

files = {
    "/etc/ssh/sshd_config": {
        'source': "sshd_config",
        'content_type': 'mako',
        'mode': "0600",
        'owner': "root",
        'group': "root",
        'needs': ['tag:pkg_openssh-server'],
        'triggers': [
            'svc_systemd:ssh:restart',
        ],
    }
}

directories = {}

for username, user_attrs in node.metadata.get('users', {}).items():
    if not user_attrs.get('delete', False):
        home = user_attrs.get('home', f"/home/{username}")

        directories[f'{home}/.ssh'] = {
            'owner': username,
            'group': username,
            'mode': "0700",
        }
        if 'ssh_pubkeys' in user_attrs.keys():
            files[f"{home}/.ssh/authorized_keys"] = {
                'content': "\n".join(sorted(user_attrs['ssh_pubkeys'], key=sort_pubkey)) + "\n",
                'content_type': 'text',
                'owner': username,
                'group': username,
                'mode': "0600",
            }
        else:
            files[f"{home}/.ssh/authorized_keys"] = {
                'delete': True,
            }
