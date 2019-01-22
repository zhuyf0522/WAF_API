#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import sys
#!/usr/bin/python 
#-*- coding=utf-8 -*-

import time

a={'ab':'First','ac':'Second','ad':'Third','ae':'Fourth'}

def test(ab='m',**kwarg):
    print(ab)
    print(kwarg.get('ae'),kwarg.get('ad'))



test(**a)
