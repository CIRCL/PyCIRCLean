#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

from bin.specific import KittenGroomerSpec


class TestBasic(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None

    def test_specific(self):
        spec = KittenGroomerSpec('tests/src', 'tests/dst')
        spec.processdir()
