from uuid import uuid5, NAMESPACE_URL

defaults = {
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
            'days_valid': 365,
            'renew_days': 90,
        },
    }
}

@metadata_reactor
def add_iptables_rule(metadata):
    if not node.has_bundle("iptables"):
        raise DoNotRunAgain

    interfaces = ['main_interface']
    interfaces += metadata.get('openssh/additional_interfaces', [])

    meta_tables = {}
    for interface in interfaces:
        meta_tables += repo.libs.iptables.accept(). \
            input(interface). \
            state_new(). \
            tcp(). \
            dest_port(metadata.get('openssh/port', 22))

    return meta_tables


@metadata_reactor
def add_check_mk_tags(metadata):
    if not node.has_bundle('check_mk_agent'):
        raise DoNotRunAgain

    return {
        'check_mk': {
            'tags': {
                'ssh': 'ssh{}'.format(metadata.get('openssh/port', '')),
            }
        }
    }


@metadata_reactor
def add_check_mk_test(metadata):
    if not node.has_bundle('check_mk_agent'):
        raise DoNotRunAgain

    tag = 'ssh{}'.format(metadata.get('openssh/port', ''))
    port = metadata.get('openssh/port', 22)

    config = {}
    description = 'Check SSH Service'
    if port != 22:
        config['port'] = port
        description += ' on Port {}'.format(port)

    active_checks = {
        'ssh': [{
            'id': str(uuid5(NAMESPACE_URL, tag)),
            'condition': {'host_tags': {tag: tag}},
            'options': {'description': description},
            'value': config
        }],
    }

    # generate global host tags for ssh
    host_tags = {
        'ssh': {
            'description': 'Services/SSH Server',
            'subtags': {
                'None': ('Nein', []),
                'ssh': ('Ja', []),
            }
        }
    }

    if port != 22:
        host_tags['ssh']['subtags'][tag] = ('Ja auf Port {}'.format(port), ['ssh', ])

    # SSH Server host_group
    host_groups = {
        'ssh-servers': {
            'description': 'SSH Server',
            'id': '0da264c0-bc48-4f83-9161-4eca6c62100a',
            'condition': {'host_tags': {'ssh': 'ssh'}},
        }
    }

    return {
        'check_mk': {
            'agent': {
                'active_checks': active_checks,
                'host_tags': host_tags,
                'host_groups': host_groups,
            }
        },
    }


