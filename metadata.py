@metadata_processor
def add_iptables_rule(metadata):
    if node.has_bundle("iptables"):
        interfaces = ['main_interface']
        interfaces += metadata.get('openssh', {}).get('additional_interfaces', [])

        for interface in interfaces:
            metadata += repo.libs.iptables.accept(). \
                input(interface). \
                state_new(). \
                tcp(). \
                dest_port(metadata.get('openssh', {}).get('port', 22))

    return metadata, DONE


@metadata_processor
def add_check_mk_tags(metadata):
    if node.has_bundle('check_mk_agent'):
        metadata.setdefault('check_mk', {})
        metadata['check_mk'].setdefault('tags', {})
        tag = 'ssh{}'.format(metadata.get('openssh', {}).get('port', ''))

        metadata['check_mk']['tags']['ssh'] = tag

    return metadata, DONE


@metadata_processor
def add_check_mk_test(metadata):
    if node.has_bundle('check_mk_agent'):
        if not metadata.get('check_mk', {}).get('servers', []):
            return metadata, RUN_ME_AGAIN

        tag = 'ssh{}'.format(metadata.get('openssh', {}).get('port', ''))
        port = metadata.get('openssh', {}).get('port', 22)

        for check_mk_server_name in metadata['check_mk']['servers']:
            check_mk_server = repo.get_node(check_mk_server_name)

            if check_mk_server.partial_metadata == {}:
                return metadata, RUN_ME_AGAIN

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

    return metadata, DONE
