import os.path
from datetime import timedelta, datetime
from pathlib import Path
from tempfile import mkdtemp

import bundlewrap.exceptions
from bundlewrap.items import Item
from bundlewrap.utils.remote import PathInfo

try:
    from sshkey_tools.cert import SSHCertificate
    from sshkey_tools.keys import PrivateKey, PublicKey
except ImportError:
    raise bundlewrap.exceptions.BundleError("Please install package sshkey-tools>=0.9 first.")


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
        'ca_password': None,
        'ca_path': None,
        'days_valid': 3650,
    }
    ITEM_TYPE_NAME = "sign_host_key"
    REQUIRED_ATTRIBUTES = [
        'ca_password',
        'ca_path',
    ]

    def get_key_path(self):
        return self.name

    def get_cert_path(self):
        return self.get_key_path() + '.pub.crt'

    def get_ca_path(self):
        return self.attributes.get('ca_path')

    def load_ca_private_key(self) -> PrivateKey:
        ca_file_local = os.path.join(self.node.repo.data_dir, self.attributes.get("ca_path"))
        if not os.path.exists(ca_file_local):
            raise Exception("No SSH CA file: ", ca_file_local)

        try:
            return PrivateKey.from_file(str(ca_file_local), password=self.attributes.get('ca_password'))
        except Exception as e:
            raise bundlewrap.exceptions.BundleError("Can't decrypt SSH CA file.", e)

    @classmethod
    def block_concurrent(cls, node_os, node_os_version):
        """
        Return a list of item types that cannot be applied in parallel
        with this item type.
        """
        return []

    def __repr__(self):
        return "<Sign Host Key path:{} ca_path:{}>".format(self.get_key_path(),
                                                                 self.get_ca_path())

    def cdict(self):
        return {
            f'{self.get_cert_path()} exist': True
        }

    def sdict(self):
        path_info = PathInfo(self.node, self.get_cert_path())
        return {
            f'{self.get_cert_path()} exist': path_info.exists
        }

    def fix(self, status):
        tmpdir = mkdtemp(prefix=self.node.name)

        pub_file_local = os.path.join(tmpdir, f'{os.path.basename(self.get_key_path())}.pub')
        cert_file_local = os.path.join(tmpdir, f'{os.path.basename(self.get_key_path())}.pub.crt')

        # Download host_key and save to temporary cert_file
        self.node.download(self.get_key_path() + '.pub', pub_file_local)

        pubkey = PublicKey.from_file(pub_file_local)
        cert = SSHCertificate.create(
            subject_pubkey=pubkey,
            ca_privkey=self.load_ca_private_key(),
        )
        cert.fields.cert_type = 2
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
