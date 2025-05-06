import re
import json
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

def load_scripts():
    scripts = json.loads(Path('scripts.json').read_text())
    return [f'{script}={path}' for script, path in scripts]

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
        'colorama',
        'coloredlogs',
        'ifcfg',
        'impacket',
        'jinja2',
        'jmespath',
        'lxml',
        'markdown<3.2',
        'markdownify',
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
        'ruamel.yaml<0.18.0',
        'scapy',
        'selenium',
        'sqlalchemy',
        'strip-ansi',
        'toolz',
        'webdav',
        'xmltodict',
        'xmljson',
        'openpyxl',
        'pycomplete',
    ],

    version=version(),
    description=(
        'Collection of utilities used across various NSI projects'
    ),
    long_description=long_description,
    long_description_content_type='text/markdown',

    url='https://github.com/NextStepInnovation/nsi-tools',

    author="David O'Gwynn",
    author_email='david_ogwynn@nextstepinnovation.com',

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
        'console_scripts': load_scripts(),
    },
)
