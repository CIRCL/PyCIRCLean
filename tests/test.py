#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import subprocess
import time


class TestBasic(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None

    def test_specific(self):
        p = subprocess.Popen(['specific.py', '-s', 'tests/src', '-d', 'tests/dst'])
        while True:
            p.poll()
            print(p.returncode)
            if p.returncode is None:
                time.sleep(1)
            else:
                return
