#!/usr/bin/python
# -*- coding: utf-8 -*-
from setuptools import setup

setup(
    name='kittengroomer',
    version='2.1',
    author='Raphaël Vinot',
    author_email='raphael.vinot@circl.lu',
    maintainer='Raphaël Vinot',
    url='https://github.com/CIRCL/CIRCLean',
    description='Standalone CIRCLean/KittenGroomer code.',
    packages=['kittengroomer'],
    scripts=[
        'bin/filecheck.py'
    ],
    classifiers=[
        'License :: OSI Approved :: BSD License',
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Science/Research',
        'Programming Language :: Python :: 3',
        'Topic :: Communications :: File Sharing',
        'Topic :: Security',
    ],
    install_requires=['twiggy', 'python-magic'],
)
