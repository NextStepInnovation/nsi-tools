import re
from pathlib import Path

from setuptools import setup, find_packages

HERE = Path(__file__).resolve().parent

version_re = re.compile(r"^__version__\s*=\s*'(?P<version>.*)'$", re.M)
def version():
    match = version_re.search(Path('nsi/__init__.py').read_text())
    if match:
        return match.groupdict()['version'].strip()
    raise AttributeError(
        'Could not find __version__ attribute in nsi/__init__.py'
    )

long_description = Path(HERE, 'README.md').resolve().read_text()

setup(
    name='nsi-tools',
    packages=find_packages(
        exclude=['tests', 'powershell'],
    ),
    package_dir={
        'nsi': 'nsi',
    },
    package_data = {
        'nsi': [
            'data/nmap-services',
            'data/*.txt',
            'data/*.csv',
            'data/*.gz',
        ],
    },

    install_requires=[
        'bs4',
        'chardet',
        'click',
        'coloredlogs',
        'ifcfg',
        'impacket',
        'jinja2',
        'jmespath',
        'lxml',
        'markdown',
        'msgpack',
        'multipledispatch',
        'networkx',
        'paramiko',
        'pillow',
        'pycryptodome',
        'pymaybe',
        'pymdown-extensions',
        'pyperclip',
        'pyrsistent',
        'python-dateutil',
        'regex',
        'requests',
        'requests[socks]',
        'ruamel.yaml',
        'toolz',
        'webdav',
        'xmljson',
        'openpyxl',
    ],

    version=version(),
    description=(
        'Collection of utilities used across various NSI projects'
    ),
    long_description=long_description,
    long_description_content_type='text/markdown',

    url='https://github.com/NextStepInnovation/nsi-tools',

    author="David O'Gwynn",
    author_email='dogwynn@lowlandresearch.com',

    license='MIT',

    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.10',
    ],

    zip_safe=False,

    keywords=('utilities functional toolz networking security infosec'),

    scripts=[
    ],

    entry_points={
        'console_scripts': [
            'diffips=nsi.cli.ips:diff_ips',
            'intips=nsi.cli.ips:int_ips',
            'difflines=nsi.cli.text:diff_lines',
            'intlines=nsi.cli.text:int_lines',
            'sortips=nsi.cli.ips:sort_ips',
            'sortbyips=nsi.cli.ips:sort_by_ips',
            'getips=nsi.cli.ips:get_ips',
            'getsubnets=nsi.cli.ips:get_subnets',
            'zpad=nsi.cli.ips:zpad_ips',
            'unzpad=nsi.cli.ips:unzpad_ips',
            'nthash=nsi.cli.hashes:nt_hash',
            'nsi-render=nsi.cli.text:render_templates',
            'nsi-secrets-crawl=nsi.secrets_crawl:secrets_crawl',
            'nsi-dump-hashes=nsi.cli.hashes:dump_hashes',
            'nsi-e4l-users=nsi.cli.enum4linux:dump_users',
            'nsi-msf-ips=nsi.cli.msf:dump_spool_ips',
            'nsi-nmap-ports=nsi.cli.nmap:nse_ports',
            'nsi-nmap-diffports=nsi.cli.nmap:diff_ports',
            'nsi-smb-shares=nsi.cli.smb:enumerate_smb_shares',
            'nsi-smb-ls=nsi.cli.smb:smb_ls',
            'nsi-dirb=nsi.cli.http:dirb_ips',
            'nsi-nikto=nsi.cli.http:nikto_ips',
            'nsi-fping-subnets=nsi.cli.fping:fping_subnets',
            'nsi-nmap=nsi.cli.nmap:nmap_hosts',
            'nsi-nmap-services=nsi.cli.nmap:nmap_services',
            'nsi-dns-resolve=nsi.cli.dns:dns_resolve',
            # 'nsi-bh-list-computers=nsi.cli.bloodhound:bloodhound_list_computers',
            # 'nsi-bh-list-users=nsi.cli.bloodhound:bloodhound_list_users',
            # 'nsi-bh-list-groups=nsi.cli.bloodhound:bloodhound_list_groups',
            'nsi-bh-list-computers=nsi.cli.bloodhound:list_computers',
            'nsi-bh-list-users=nsi.cli.bloodhound:list_users',
            'nsi-bh-list-groups=nsi.cli.bloodhound:list_groups',
            'nsi-bh-group-members=nsi.cli.bloodhound:group_members',
            'nsi-bh-user-groups=nsi.cli.bloodhound:user_groups',
            'nsi-whois=nsi.cli.whois:whois_ips',
            'nsi-ftp=nsi.cli.ftp:main',
            'nsi-secretsdump=nsi.cli.secretsdump:dump',
            'nsi-ntlm-resolve=nsi.cli.ntlm:resolve',
            'nsi-ntlm-extract=nsi.cli.ntlm:extract',
            'nsi-filesystem-meta=nsi.cli.filesystem:metadata',
        ],
    },
)
