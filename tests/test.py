#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import os

from bin.specific import KittenGroomerSpec
from bin.pier9 import KittenGroomerPier9
from bin.generic import KittenGroomer

from kittengroomer import FileBase


class TestBasic(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None
        self.curpath = os.getcwd()

    def test_specific(self):
        src = os.path.join(self.curpath, 'tests/src')
        dst = os.path.join(self.curpath, 'tests/dst')
        spec = KittenGroomerSpec(src, dst)
        spec.processdir()

    def test_pier9(self):
        src = os.path.join(self.curpath, 'tests/src')
        dst = os.path.join(self.curpath, 'tests/dst')
        spec = KittenGroomerPier9(src, dst)
        spec.processdir()

    def test_generic(self):
        src = os.path.join(self.curpath, 'tests/src')
        dst = os.path.join(self.curpath, 'tests/dst')
        spec = KittenGroomer(src, dst)
        spec.processdir()

    def test_help_file(self):
        f = FileBase('tests/src/blah.conf', 'tests/dst/blah.conf')
        f.make_unknown()
        f.make_binary()
        f.make_unknown()
        f.make_dangerous()
        f.make_binary()
        f.make_dangerous()
