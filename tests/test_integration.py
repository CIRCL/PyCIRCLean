#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

import kittengroomer as kg
import bin.specific as specific

PATH = os.getcwd() + '/tests/'


def test_base():
    assert kg.FileBase
    assert kg.KittenGroomerBase
    assert kg.main


def test_help_file():
        f = kg.FileBase('tests/src_complex/blah.conf', 'tests/dst/blah.conf')
        f.make_unknown()
        f.make_binary()
        f.make_unknown()
        f.make_dangerous()
        f.make_binary()
        f.make_dangerous()
