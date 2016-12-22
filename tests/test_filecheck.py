#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pytest

from bin.filecheck import KittenGroomerFileCheck, File, main


class TestFileHandling:
    pass

    # We're going to give KittenGroomer a bunch of files, and it's going to process them
    # Maybe we want to make a function that processdir delegates to? Or is it just the File Object that's responsible?
    # Ideally we should be able to pass a path to a function and have it do stuff? And then we can test that function?
    # So we have a function that takes a path and returns...log info? That makes sense actually. Or some sort of meta data
    # The function could maybe be called processfile
