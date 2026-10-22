"""Reject private user data in package payloads without logging file contents."""
import argparse
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import zipfile

PRIVATE_SUFFIX = re.compile(r'\.(?:db|sqlite3?)(?:$|[.-])', re.IGNORECASE)
PRIVATE_HEADERS = (b'SQLite format 3\x00', b'%PDF-', b'-----BEGIN PRIVATE KEY',
                   b'-----BEGIN RSA PRIVATE KEY', b'-----BEGIN OPENSSH PRIVATE KEY')


def check_name(name):
    lower = name.replace('\\', '/').lower()
    leaf = PurePosixPath(lower).name
    if (PRIVATE_SUFFIX.search(lower) or leaf.endswith(('.pdf', '.pem', '.key', '.jks', '.keystore'))
            or leaf in ('passwords.txt', 'master_key.txt') or leaf.startswith('.env')):
        raise ValueError(f'Private-data filename found: {name}')


def check_header(stream):
    if stream.read(128).startswith(PRIVATE_HEADERS):
        raise ValueError('Private database, document, or key payload found')


def check_zip(path):
    checked = 0
    with zipfile.ZipFile(path) as archive:
        for member in archive.infolist():
            check_name(member.filename)
            if member.is_dir():
                continue
            with archive.open(member) as stream:
                check_header(stream)
            checked += 1
    return checked


def check_tar(archive):
    checked = 0
    for member in archive:
        check_name(member.name)
        if member.isfile():
            with archive.extractfile(member) as stream:
                check_header(stream)
            checked += 1
    return checked


def check_tree(path):
    path = Path(path)
    root = path.resolve()
    if not path.is_dir():
        raise ValueError('Package directory does not exist')
    checked = 0
    for item in path.rglob('*'):
        check_name(item.relative_to(path).as_posix())
        if item.is_symlink() and not item.resolve().is_relative_to(root):
            raise ValueError('Package symlink points outside the payload')
        if item.is_file():
            with item.open('rb') as stream:
                check_header(stream)
            if item.suffix.lower() in ('.zip', '.apk', '.aab'):
                check_zip(item)
            checked += 1
    return checked


def check_archive(path):
    path = Path(path)
    check_name(path.name)
    if not path.is_file():
        raise ValueError('Package file does not exist')
    if path.suffix.lower() in ('.zip', '.apk', '.aab'):
        return check_zip(path)
    if path.name.endswith(('.tar.gz', '.tar.xz', '.tar')):
        with tarfile.open(path, 'r:*') as archive:
            return check_tar(archive)
    if path.suffix.lower() == '.deb':
        process = subprocess.Popen(['dpkg-deb', '--fsys-tarfile', str(path)], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        try:
            with tarfile.open(fileobj=process.stdout, mode='r|') as archive:
                checked = check_tar(archive)
            if process.wait() != 0:
                raise ValueError('Could not inspect the Debian package')
            return checked
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate()
    # EXE/DMG containers are built exclusively from a checked application tree.
    # Their payload is checked before invoking Inno Setup/hdiutil.
    raise ValueError('Unsupported archive; inspect its staging directory before packaging')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('paths', nargs='+', type=Path)
    args = parser.parse_args()
    count = 0
    for path in args.paths:
        count += check_tree(path) if path.is_dir() else check_archive(path)
    print(f'Package privacy check passed ({count} payload files inspected)')


if __name__ == '__main__':
    main()
