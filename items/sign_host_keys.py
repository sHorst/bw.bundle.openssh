from tempfile import gettempdir

from bundlewrap.items import Item
from bundlewrap.utils.remote import PathInfo
from sshkey_tools.cert import SSHCertificate
from sshkey_tools.keys import PrivateKey, PublicKey
from bundlewrap.repo import Repository


class SignHostKeys(Item):
    """
    Sign SSH Host Keys
    """
    BUNDLE_ATTRIBUTE_NAME = "sign_host_keys"
    NEEDS_STATIC = [
    ]
    ITEM_ATTRIBUTES = {
        'key_format': None,
        'ca_password': None,
        'hostkey_file': None,
        'ca_path': None,
        'days_valid': 3650,
    }
    ITEM_TYPE_NAME = "sign_host_key"
    REQUIRED_ATTRIBUTES = [
        'key_format',
        'ca_password',
        'ca_path',
    ]

    @classmethod
    def block_concurrent(cls, node_os, node_os_version):
        """
        Return a list of item types that cannot be applied in parallel
        with this item type.
        """
        return []

    def __repr__(self):
        return "<Sign Host Key key_format:{} ca_path:{}>".format(self.attributes['key_format'], self.attributes['ca_path'])

    def cdict(self):
        filename = '/etc/ssh_host_{}_key-cert.pub'.format(self.attributes.get('key_format'))
        return {
            f'{filename} exist': True
        }

    def sdict(self):
        filename = '/etc/ssh_host_{}_key-cert.pub'.format(self.attributes.get('key_format'))
        path_info = PathInfo(self.node, filename)
        return {
            f'{filename} exist': path_info.exists
        }

    def display_on_create(self, cdict):
        """
        Given a cdict as implemented above, modify it to better suit
        interactive presentation when an item is created. If there are
        any when_creating attributes, they will be added to the cdict
        before it is passed to this method.

        Implementing this method is optional.
        """
        return cdict

    def display_dicts(self, cdict, sdict, keys):
        """
        Given cdict and sdict as implemented above, modify them to
        better suit interactive presentation. The keys parameter is a
        list of keys whose values differ between cdict and sdict.

        Implementing this method is optional.
        """
        return (cdict, sdict, keys)

    def display_on_delete(self, sdict):
        """
        Given an sdict as implemented above, modify it to better suit
        interactive presentation when an item is deleted.

        Implementing this method is optional.
        """
        return sdict

    def fix(self, status):
        pub_file_local = f'{gettempdir()}/ssh_host_{self.attributes.get("key_format")}_key.pub'
        cert_file_local = f'{gettempdir()}/ssh_host_{self.attributes.get("key_format")}_key-cert.pub'
        host_key = f'/etc/ssh/ssh_host_{self.attributes.get("key_format")}_key.pub'
        if self.attributes.get('hostkey_file'):
            host_key = self.attributes.get('hostkey_file')

        # Download host_key and save to temporary cert_file
        self.node.download(host_key, pub_file_local)

        ca = PrivateKey.from_file(f'./data/{self.attributes.get("ca_path")}', password=self.attributes.get('ca_password'))

        pubkey = PublicKey.from_file(host_key)
        cert = SSHCertificate.create(
            subject_pubkey=pubkey,
            ca_privkey=ca,
        )
        cert.sign()

        cert.to_file(filename=cert_file_local)

        self.node.upload(
            cert_file_local,
            f'/etc/ssh/ssh_host_{self.attributes.get("key_format")}_key-cert.pub',
            '0644',
            'root',
            'root'
        )

        return True
