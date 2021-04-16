from setuptools import setup, find_packages

setup_params = dict(
    name='epp-python-client',
    version='0.0.1',
    author='Veselin Penev',
    author_email='penev.veselin@gmail.com',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    scripts=['bin/epp-gate', ],
    description='Python-based Extensible Provisioning Protocol (EPP) client',
    long_description=(
        "The library provides an interface to the Extensible Provisioning "
        "Protocol (EPP), which is being used for communication between domain "
        "name registries and domain name registrars."
    ),
    url='https://github.com/datahaven-net/epp-python-client',
    install_requires=[
        "beautifulsoup4",
        "lxml",
    ],
)

def run_setup():
    setup(**setup_params)

if __name__ == '__main__':
    run_setup()
