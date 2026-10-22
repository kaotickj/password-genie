"""Build only reviewed code and icons; never collect directories of user data."""
import os
import ctypes
from pathlib import Path
import platform
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from vault_core import VERSION
from check_package_contents import check_tree, check_archive


def run(*args):
    subprocess.run([str(arg) for arg in args], cwd=ROOT, check=True)


def main():
    os.chdir(ROOT)
    out = ROOT / 'dist'
    staging = ROOT / 'build' / 'package'
    staging.mkdir(parents=True, exist_ok=True)
    system = platform.system().lower()
    arch = platform.machine().lower()
    name = f'PasswordGenie-{VERSION}-{system}-{arch}'
    icon = 'icon.ico' if system == 'windows' else 'icon.png'
    if system == 'darwin':
        from PIL import Image
        icon = str(staging / 'icon.icns')
        Image.open(ROOT / 'icon.png').save(icon, format='ICNS')
    command = [sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean',
        '--windowed', '--onedir', '--name', 'PasswordGenie', '--icon', icon,
        '--add-data', f'icon.png{os.pathsep}.', '--add-data', f'icon.ico{os.pathsep}.',
        '--exclude-module', 'tkinter', 'pwgenie.py']
    run(*command)
    payload = out / ('PasswordGenie.app' if system == 'darwin' else 'PasswordGenie')
    check_tree(payload)
    print('Application payload privacy check passed', flush=True)
    if system == 'linux':
        package = staging / name
        # Start fresh so stale files can never survive into a new installer.
        if package.exists():
            shutil.rmtree(package)
        (package / 'opt' / 'password-genie').mkdir(parents=True, exist_ok=True)
        shutil.copytree(out / 'PasswordGenie', package / 'opt' / 'password-genie', dirs_exist_ok=True)
        applications = package / 'usr' / 'share' / 'applications'
        applications.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / 'packaging' / 'password-genie.desktop', applications)
        icons = package / 'usr' / 'share' / 'icons' / 'hicolor' / '256x256' / 'apps'
        icons.mkdir(parents=True, exist_ok=True)
        from PIL import Image
        Image.open(ROOT / 'icon.png').resize((256, 256)).save(icons / 'password-genie.png')
        debian = package / 'DEBIAN'
        debian.mkdir(exist_ok=True)
        deb_arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}[arch]
        libc = ctypes.CDLL(None)
        libc.gnu_get_libc_version.restype = ctypes.c_char_p
        glibc = libc.gnu_get_libc_version().decode('ascii')
        (debian / 'control').write_text(f'''Package: password-genie
Version: {VERSION}
Architecture: {deb_arch}
Maintainer: Kaotick Jay <kaotickj@users.noreply.github.com>
Depends: libc6 (>= {glibc}), libgl1, libegl1, libxkbcommon0, libxkbcommon-x11-0, libxcb-cursor0, libxcb-icccm4, libxcb-image0, libxcb-keysyms1, libxcb-render-util0, libxcb-xinerama0, libxcb-randr0, libxcb-shape0, libxcb-xfixes0, libxcb-sync1, libxcb-render0, libxcb-shm0, libxcb-xkb1, libdbus-1-3, libfontconfig1, libfreetype6
Section: utils
Priority: optional
Description: Local encrypted credential vault and password generator
''')
        for path in package.rglob('*'):
            if path.is_dir(): path.chmod(0o755)
        check_tree(package)
        run('dpkg-deb', '--root-owner-group', '--build', package, out / (name + '.deb'))
        shutil.make_archive(str(out / name), 'gztar', root_dir=out, base_dir='PasswordGenie')
        check_archive(out / (name + '.deb'))
        check_archive(out / (name + '.tar.gz'))
    elif system == 'darwin':
        dmg = staging / 'dmg'
        if dmg.exists():
            shutil.rmtree(dmg)
        dmg.mkdir()
        shutil.copytree(out / 'PasswordGenie.app', dmg / 'PasswordGenie.app', dirs_exist_ok=True, symlinks=True)
        (dmg / 'Applications').symlink_to('/Applications', target_is_directory=True)
        run('hdiutil', 'create', '-volname', 'Password Genie', '-srcfolder', dmg,
            '-ov', '-format', 'UDZO', out / (name + '.dmg'))
    elif system == 'windows':
        compiler = shutil.which('ISCC') or r'C:\Program Files (x86)\Inno Setup 6\ISCC.exe'
        run(compiler, f'/DAppVersion={VERSION}', ROOT / 'packaging' / 'windows.iss')
    else:
        raise SystemExit(f'Unsupported OS: {system}')


if __name__ == '__main__':
    main()
