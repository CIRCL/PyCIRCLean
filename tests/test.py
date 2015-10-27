#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

from bin.specific import KittenGroomerSpec
from bin.pier9 import KittenGroomerPier9
from bin.generic import KittenGroomer


class TestBasic(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None

    def test_specific(self):
        spec = KittenGroomerSpec('tests/src', 'tests/dst')
        spec.processdir()

    def test_pier9(self):
        spec = KittenGroomerPier9('tests/src', 'tests/dst')
        spec.processdir()

    def test_generic(self):
        spec = KittenGroomer('tests/src', 'tests/dst')
        spec.processdir()
