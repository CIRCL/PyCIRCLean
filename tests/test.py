#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import os
import sys

from bin.specific import KittenGroomerSpec
from bin.pier9 import KittenGroomerPier9
from bin.generic import KittenGroomer

if sys.version_info.major == 2:
    from bin.filecheck import KittenGroomerFileCheck

from kittengroomer import FileBase


class TestBasic(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None
        self.curpath = os.getcwd()

    def dump_logs(self):
        logfile = os.path.join(self.curpath, 'tests/dst/logs/processing.log')
        print(open(logfile, 'rb').read())

    def test_specific_valid(self):
        src = os.path.join(self.curpath, 'tests/src2')
        dst = os.path.join(self.curpath, 'tests/dst')
        spec = KittenGroomerSpec(src, dst)
        spec.processdir()
        self.dump_logs()

    def test_specific_invalid(self):
        src = os.path.join(self.curpath, 'tests/src')
        dst = os.path.join(self.curpath, 'tests/dst')
        spec = KittenGroomerSpec(src, dst)
        spec.processdir()
        self.dump_logs()

    def test_pier9(self):
        src = os.path.join(self.curpath, 'tests/src')
        dst = os.path.join(self.curpath, 'tests/dst')
        spec = KittenGroomerPier9(src, dst)
        spec.processdir()
        self.dump_logs()

    def test_generic(self):
        src = os.path.join(self.curpath, 'tests/src')
        dst = os.path.join(self.curpath, 'tests/dst')
        spec = KittenGroomer(src, dst)
        spec.processdir()
        self.dump_logs()

    def test_filecheck(self):
        if sys.version_info.major >= 3:
            return
        src = os.path.join(self.curpath, 'tests/src')
        dst = os.path.join(self.curpath, 'tests/dst')
        spec = KittenGroomerFileCheck(src, dst)
        spec.processdir()
        self.dump_logs()

    def test_help_file(self):
        f = FileBase('tests/src/blah.conf', 'tests/dst/blah.conf')
        f.make_unknown()
        f.make_binary()
        f.make_unknown()
        f.make_dangerous()
        f.make_binary()
        f.make_dangerous()
