import re
from pathlib import Path

from setuptools import setup, find_packages

HERE = Path(__file__).resolve().parent

version_re = re.compile(r"^__version__\s*=\s*'(?P<version>.*)'$", re.M)
def version():
    match = version_re.search(Path('nsi/__init__.py').read_text())
    if match:
        return match.groupdict()['version'].strip()
    return '0.0.1'

long_description = Path(HERE, 'README.md').resolve().read_text()

setup(
    name='nsi',
    packages=find_packages(
        exclude=['tests'],
    ),
    package_dir={
        'nsi': 'nsi',
    },

    install_requires=[
        'toolz',
        'pymaybe',
        'pyrsistent',
        'coloredlogs',
        'ruamel.yaml',
        'click',
        'paramiko',
        'xmljson',
        'python-dateutil',
        'jmespath',
        'ifcfg',
        'markdown',
        'jinja2',
        'pillow',
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

    keywords=('utilities functional toolz networking security'),

    scripts=[
    ],

    entry_points={
        'console_scripts': [
            'diffips=nsi.cli.ips:diff_ips',
            'intips=nsi.cli.ips:int_ips',
            'difflines=nsi.cli.text:diff_lines',
            'intlines=nsi.cli.text:int_lines',
            'sortips=nsi.cli.ips:sort_ips',
            'getips=nsi.cli.ips:get_ips',
            'getsubnets=nsi.cli.ips:get_subnets',
            'zpad=nsi.cli.ips:zpad_ips',
            'unzpad=nsi.cli.ips:unzpad_ips',
            'nsi-render=nsi.cli.text:render_templates'
        ],
    },
)
