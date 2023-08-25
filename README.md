OpenSSH Module
--------------

This module installes Openssh. It also installes firewall rules and check_mk tasks.

If you define `openssh{sign_host_key{[something]}` it will also generate signes host keys.

Use signed host keys
-------------
- Generate a password protected SSH CA
- Place the CA file in `data/certs/ssh_ca` (default value)
- Add password to your metadata (see below)
- Link the `items/sign_host_keys.py` to your `[repo]/items` folder.
- Install `sshkey-tools>=0.9` via `pip`.
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
    'additional_interfaces': ['private'], # Optional
    'port': 22, # Optional
    'password_auth': False, # Optional
    'gateway_ports': False, # Optional
    'sign_host_keys': {
        'ca_path': 'certs/ssh_ca', # Password protected and not encrypted by bundlewrap
        'ca_password': 'foobar'
        'formats': [
            'ed25519',
            'ecdsa',
        ],
    },
},
```
