pkg_apt = {
    "openssh-server": {},
}

files = {
    "/etc/ssh/sshd_config": {
        'source': "sshd_config",
        'content_type': 'mako',
        'mode': "0600",
        'owner': "root",
        'group': "root",
        'needs': ['pkg_apt:openssh-server'],
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
        files["/home/{}/.ssh/authorized_keys".format(username)] = {
            'content': "\n".join(user_attrs['ssh_pubkeys']) + "\n",
            'owner': username,
            'group': username,
            'mode': "0600",
        }
