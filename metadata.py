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


# TODO: check if this is still working
@metadata_reactor
def add_check_mk_test(metadata):
    # TODO: fix this
    raise DoNotRunAgain


    if not node.has_bundle('check_mk_agent'):
        raise DoNotRunAgain

    if not metadata.get('check_mk/servers', []):
        return {}

    tag = 'ssh{}'.format(metadata.get('openssh/port', ''))
    port = metadata.get('openssh/port', 22)

    for check_mk_server_name in metadata.get('check_mk/servers'):
        check_mk_server = repo.get_node(check_mk_server_name)

        if check_mk_server.partial_metadata == {}:
            return {}

        check_mk_server.partial_metadata.\
            setdefault('check_mk', {}). \
            setdefault('global_rules', {}). \
            setdefault('active_checks', {}). \
            setdefault('ssh', [])

        for active_checks in check_mk_server.partial_metadata['check_mk']['global_rules']['active_checks']['ssh']:
            if tag in list(active_checks.get('condition', {}).get('host_tags', {}).keys()):
                break
        else:
            config = {}
            description = 'Check SSH Service'
            if port != 22:
                config['port'] = port
                description += ' on Port {}'.format(port)

            check_mk_server.partial_metadata['check_mk']['global_rules']['active_checks']['ssh'] += [
                {
                    'condition': {'host_tags': {tag: tag}},
                    'options': {'description': description},
                    'value': config
                },
            ]

        # generate global host tags for ssh
        check_mk_server.partial_metadata. \
            setdefault('check_mk', {}). \
            setdefault('host_tags', {}). \
            setdefault('ssh', {
                'description': 'Services/SSH Server',
                'subtags': {
                    'None': ('Nein', []),
                    'ssh': ('Ja', []),
                }
            })

        if tag not in check_mk_server.partial_metadata['check_mk']['host_tags']['ssh']['subtags']:
            check_mk_server.partial_metadata['check_mk']['host_tags']['ssh']['subtags'][tag] = (
                'Ja auf Port {}'.format(port), ['ssh', ]
            )

        # SSH Server host_group
        check_mk_server.partial_metadata. \
            setdefault('check_mk', {}). \
            setdefault('host_groups', {})

        check_mk_server.partial_metadata['check_mk']['host_groups']['ssh-servers'] = {
            'description': 'SSH Server',
            'condition': {'host_tags': {'ssh': 'ssh'}},
        }

    return {}
