#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

import kittengroomer as kg
from kittengroomer import FileBase
import PyCIRCLean.bin.specific as specific

PATH = os.getcwd() + '/tests/'


def test_base():
    assert kg.FileBase
    assert kg.KittenGroomerBase
    assert kg.main


def test_specific():
    src = os.path.join(PATH, 'src2')
    dst = os.path.join(PATH, 'dst')
    spec = specific.KittenGroomerSpec(src, dst, debug=True)
    spec.processdir()


def test_help_file():
        f = FileBase('tests/src/blah.conf', 'tests/dst/blah.conf')
        f.make_unknown()
        f.make_binary()
        f.make_unknown()
        f.make_dangerous()
        f.make_binary()
        f.make_dangerous()
