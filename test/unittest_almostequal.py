#!/usr/bin/python
#-*- coding= utf-8 -*-
""" assertAlmostEuqal and assertNotAlmostEuqal """

import unittest
import HTMLTestRunner

def raise_exec():
    raise Exception('ErrorExce')
class AlmostTest(unittest.TestCase):
    def testAlmost(self):
        self.assertAlmostEqual(1.111,1.1123,2)

    def testNotalmost(self):
        self.assertNotAlmostEqual(1.111,1.1123,3)

class ItemEqual(unittest.TestCase):
    def testItemEqual(self):
#        self.assertItemsEqual([3,6,9],[6,9,3])
        self.assertRaises(Exception,raise_exec)
        print(id(self))
if __name__ == '__main__':
    suite=unittest.TestSuite()
    suite.addTest(unittest.makeSuite(AlmostTest))
    suite.addTest(unittest.makeSuite(ItemEqual))
#    fw=open('almost.html','wb')
#    runner=HTMLTestRunner.HTMLTestRunner(stream=fw,title='unittest result',description='assertAlmostEqual and asserNotAlmostEqual test')
    print(suite.countTestCases())
    runner=unittest.TextTestRunner(verbosity=2)
    runner.run(suite)
