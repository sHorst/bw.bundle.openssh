OpenSSH Module
--------------

This module installes Openssh. It also installes firewall rules and check_mk tasks

Demo Metadata
-------------

These metadata keys are used

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
    'additional_interfaces': ['private'],
    'port': 22, # Optional
    'password_auth': False, # Optional
    'gateway_ports': False, # Optional
},
```
