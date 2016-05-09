#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import os
import sys

if __name__ == '__main__':
    sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))

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

    def dump_logs(self, kg):
        print(open(kg.log_processing, 'rb').read())
        if kg.debug:
            if os.path.exists(kg.log_debug_err):
                print(open(kg.log_debug_err, 'rb').read())
            if os.path.exists(kg.log_debug_out):
                print(open(kg.log_debug_out, 'rb').read())

    def test_specific_valid(self):
        src = os.path.join(self.curpath, 'tests/src2')
        dst = os.path.join(self.curpath, 'tests/dst')
        spec = KittenGroomerSpec(src, dst, debug=True)
        spec.processdir()
        self.dump_logs(spec)

    def test_specific_invalid(self):
        src = os.path.join(self.curpath, 'tests/src')
        dst = os.path.join(self.curpath, 'tests/dst')
        spec = KittenGroomerSpec(src, dst, debug=True)
        spec.processdir()
        self.dump_logs(spec)

    def test_pier9(self):
        src = os.path.join(self.curpath, 'tests/src')
        dst = os.path.join(self.curpath, 'tests/dst')
        spec = KittenGroomerPier9(src, dst, debug=True)
        spec.processdir()
        self.dump_logs(spec)

    def test_generic(self):
        src = os.path.join(self.curpath, 'tests/src2')
        dst = os.path.join(self.curpath, 'tests/dst')
        spec = KittenGroomer(src, dst, debug=True)
        spec.processdir()
        self.dump_logs(spec)

    def test_generic_2(self):
        src = os.path.join(self.curpath, 'tests/src')
        dst = os.path.join(self.curpath, 'tests/dst')
        spec = KittenGroomer(src, dst, debug=True)
        spec.processdir()
        self.dump_logs(spec)

    def test_filecheck(self):
        if sys.version_info.major >= 3:
            return
        src = os.path.join(self.curpath, 'tests/src')
        dst = os.path.join(self.curpath, 'tests/dst')
        spec = KittenGroomerFileCheck(src, dst, debug=True)
        spec.processdir()
        self.dump_logs(spec)

    def test_filecheck_2(self):
        if sys.version_info.major >= 3:
            return
        src = os.path.join(self.curpath, 'tests/src2')
        dst = os.path.join(self.curpath, 'tests/dst')
        spec = KittenGroomerFileCheck(src, dst, debug=True)
        spec.processdir()
        self.dump_logs(spec)

    def test_help_file(self):
        f = FileBase('tests/src/blah.conf', 'tests/dst/blah.conf')
        f.make_unknown()
        f.make_binary()
        f.make_unknown()
        f.make_dangerous()
        f.make_binary()
        f.make_dangerous()
