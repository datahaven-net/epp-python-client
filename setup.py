from setuptools import setup, find_packages

setup(
    name='epp-python-client',
    version='0.0.1',
    author='Veselin Penev',
    author_email='penev.veselin@gmail.com',
    packages=find_packages(),
    description='Python-based Extensible Provisioning Protocol (EPP) client',
    long_description=(
        "The library provides an interface to the Extensible Provisioning "
        "Protocol (EPP), which is being used for communication between domain "
        "name registries and domain name registrars."
    ),
    install_requires=[
        "beautifulsoup4",
        "lxml",
    ],
)
