import os.path
from datetime import timedelta, datetime
from pathlib import Path
from tempfile import mkdtemp

import bundlewrap.exceptions
from bundlewrap.items import Item
from bundlewrap.utils.remote import PathInfo
from sshkey_tools.cert import SSHCertificate
from sshkey_tools.keys import PrivateKey, PublicKey


# See https://stackoverflow.com/a/49782093
def remove_dir_recursive(path):
    directory = Path(path)
    for item in directory.iterdir():
        if item.is_dir():
            os.rmdir(item)
        else:
            item.unlink()
    directory.rmdir()


class SignHostKeys(Item):
    """
    Sign SSH Host Keys
    """
    BUNDLE_ATTRIBUTE_NAME = "sign_host_keys"
    NEEDS_STATIC = [
        "pkg_apt:",
        "pkg_pacman:",
        "pkg_yum:",
        "pkg_zypper:",
    ]
    ITEM_ATTRIBUTES = {
        'key_format': None,
        'ca_password': None,
        'ca_path': None,
        'days_valid': 3650,
    }
    ITEM_TYPE_NAME = "sign_host_key"
    REQUIRED_ATTRIBUTES = [
        'key_format',
        'ca_password',
        'ca_path',
    ]

    def get_cert_path(self):
        return os.path.join('/', 'etc', 'ssh', f'ssh_host_{self.attributes.get("key_format")}_key-cert.pub')

    @classmethod
    def block_concurrent(cls, node_os, node_os_version):
        """
        Return a list of item types that cannot be applied in parallel
        with this item type.
        """
        return []

    def __repr__(self):
        return "<Sign Host Key key_format:{} ca_path:{}>".format(self.attributes['key_format'],
                                                                 self.attributes['ca_path'])

    def cdict(self):
        return {
            f'{self.get_cert_path()} exist': True
        }

    def sdict(self):
        path_info = PathInfo(self.node, self.get_cert_path())
        return {
            f'{self.get_cert_path()} exist': path_info.exists
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
        tmpdir = mkdtemp()

        pub_file_local = os.path.join(tmpdir, f'ssh_host_{self.attributes.get("key_format")}_key.pub')
        cert_file_local = os.path.join(tmpdir, f'ssh_host_{self.attributes.get("key_format")}_key-cert.pub')
        ca_file_local = os.path.join(self.node.repo.data_dir, self.attributes.get("ca_path"))
        host_key = os.path.normpath(
            os.path.join('/', 'etc', 'ssh', f'ssh_host_{self.attributes.get("key_format")}_key.pub')
        )

        if not os.path.exists(ca_file_local):
            raise Exception("No SSH CA file: ", ca_file_local)

        try:
            ca = PrivateKey.from_file(ca_file_local, password=self.attributes.get('ca_password'))
        except Exception as e:
            raise bundlewrap.exceptions.BundleError("Can't decrypt SSH CA file.", e)

        # Download host_key and save to temporary cert_file
        self.node.download(host_key, pub_file_local)

        pubkey = PublicKey.from_file(host_key)
        cert = SSHCertificate.create(
            subject_pubkey=pubkey,
            ca_privkey=ca,
        )
        cert.fields.valid_after = datetime.now()
        cert.fields.valid_before = datetime.now() + timedelta(days=self.attributes.get('days_valid'))
        cert.sign()
        cert.to_file(filename=cert_file_local)

        self.node.upload(
            cert_file_local,
            self.get_cert_path(),
            '0644',
            'root',
            'root'
        )

        remove_dir_recursive(tmpdir)
