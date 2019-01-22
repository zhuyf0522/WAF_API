#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Basic unitest scripts！
"""

import unittest
import HTMLTestRunner

class StringTest(unittest.TestCase):
    def setUp(self):
        print('init test setup!')
    
    def tearDown(self):
        print('end test by teardown!')

    def testUpper(self):
        self.assertEqual('foo'.upper(),'FOO')

    def testIsUpper(self):
        self.assertTrue('FOO'.isupper())
        self.assertTrue('Foo'.isupper())

    def testSplit(self):
        str='Hello World !'
        self.assertEqual(str.split(),['Hello','World','!'])


if __name__=='__main__':
    test_suite=unittest.TestSuite()
#    tes_t_suite.addTest(StringTest('testUpper'))
    test_suite.addTest(unittest.makeSuite(StringTest))
    fw=open('test.html','wb')
    runner=HTMLTestRunner.HTMLTestRunner(stream=fw,title='Test Result',description='RE-miaoshu')
    runner.run(test_suite)
