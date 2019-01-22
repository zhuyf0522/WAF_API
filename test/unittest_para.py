#!/usr/bin/python
#-*- coding= utf-8 -*-
""" unittest for parameters """

import unittest 
import HTMLTestRunner
from nose_parameterized import parameterized

def login(username,password):
    if username =='xiaogang' and password =='123456' :
        return True
    else: 
        return False

class LoginTest(unittest.TestCase):
    @parameterized.expand(
        [
            ['aaa','3455',True],
            ['bbbb','9340',True],
            ['cccc','23r4324',False],
            ['xiaogang','123456',True]
        ]
    )
    def testLogin(self,username,password,exception):
        '''login'''
        print('username= %s, password= %s' %(username,password))
        res=login(username,password)
        self.assertEqual(res,exception)

if __name__=='__main__':
    suite=unittest.TestSuite()
    suite.addTest(unittest.makeSuite(LoginTest))
    fw= open('a.html','wb')
    runner= HTMLTestRunner.HTMLTestRunner(stream=fw,title='Test unittest parameters function',description='Test Result')
    runner.run(suite)

