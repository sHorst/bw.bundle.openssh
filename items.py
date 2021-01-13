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
else:
    raise "{os} isn't supported by openssh-Bundle, yet.".format(os=node.os)

files = {
    "/etc/ssh/sshd_config": {
        'source': "sshd_config",
        'content_type': 'mako',
        'mode': "0600",
        'owner': "root",
        'group': "root",
        'needs': ['tag:pkg_openssh-server'],
    }
}

directories = {}

for username, user_attrs in node.metadata.get('users', {}).items():
    if not user_attrs.get('delete', False):
        directories["/home/{}/.ssh".format(username)] = {
            'owner': username,
            'group': username,
            'mode': "0700",
        }
        if 'ssh_pubkeys' in user_attrs.keys():
            files["/home/{}/.ssh/authorized_keys".format(username)] = {
                'content': "\n".join(user_attrs['ssh_pubkeys']) + "\n",
                'owner': username,
                'group': username,
                'mode': "0600",
            }
        else:
            files["/home/{}/.ssh/authorized_keys".format(username)] = {
                'delete': True,
            }
