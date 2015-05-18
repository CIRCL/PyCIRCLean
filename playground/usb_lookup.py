#!/usr/bin/env python
# -*- coding: utf-8 -*-

from usb.core import find
import usb.control


def is_mass_storage(dev):
    import usb.util
    for cfg in dev:
        if usb.util.find_descriptor(cfg, bInterfaceClass=8) is not None:
            return True


for mass in find(find_all=True, custom_match=is_mass_storage):
    print(mass)
