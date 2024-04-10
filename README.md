OpenSSH Module
--------------

This module installes Openssh. It also installes firewall rules and check_mk tasks.

If you define `openssh{sign_host_key{[something]}` it will also generate signed host keys.

Use signed host keys
-------------
- Generate a password protected SSH CA
- Place the CA file in `data/certs/ssh_ca` (default value)
- Add password to your metadata (see below)
- Link the `items/sign_host_keys.py` to your `[repo]/items` folder.
- Install `sshkey-tools>=0.9` via `pip`.
- Add `sshkey-tools>=0.9` to `requirements.txt`.
- Run bundlewrap
- Add `@cert-authority * [your SSH CA pubkey]` to `~/.ssh/known_hosts`

Demo Metadata
-------------

These metadata keys are used, but all optional

```python
'users': {
    'stefan': {
        # Optional
        'ssh_pubkeys': [
            "ssh-rsa AAAAB3[...]c7w== stefan",
        ]
    },
},
'openssh': {
    'port': 22,
    'additional_interfaces': [],
    'only_allow_secure_ciphers': True,
    'permit_root_login': False,
    'permit_root_login_prohibit_password': False,
    'password_auth': False,
    'use_pam': False,
    'gateway_ports': False,
    'x11': False,
    'print_motd': True,
    'use_dns': False,
    'sign_host_keys': {
        'enabled': False,
        'formats': [
            'ed25519',
            'ecdsa',
        ],
        'ca_path': 'certs/ssh_ca',
        'ca_password': '',
    },
},
```
