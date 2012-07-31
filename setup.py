#!/usr/bin/env python
from distribute_setup import use_setuptools
use_setuptools()

from setuptools import setup
import re

def load_version(filename='tls/version.py'):
    "Parse a __version__ number from a source file"
    with open(filename) as source:
        text = source.read()
        match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]", text)
        if not match:
            msg = "Unable to find version number in {}".format(filename)
            raise RuntimeError(msg)
        version = match.group(1)
        return version

setup(
    name='opentls',
    version=load_version(),
    packages=['tls'],
    zip_safe=False,
    author='Aaron Iles',
    author_email='aaron.iles@gmail.com',
    url='https://github.com/aliles/opentls',
    description='Cryptographic APIs for Python using OpenSSL',
    long_description=open('README.rst').read(),
    license='ASL',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Networking'
    ],
    install_requires=['cffi==0.2.1'],
    tests_require=['mock', 'unittest2'],
    test_suite="unittest2.collector"
)
