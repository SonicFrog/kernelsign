#!/usr/bin/python3
# Test fixtures for kernsign
# (C) 2014 Ogier Bouvier

import os
import random
import unittest
import kernsign
import gnupg


# Test fixtures for kernsign.py
class TestKernelSign(unittest.TestCase):
    def setUp(self):
        self.data = os.urandom(random.randrange(100))
        kernsign.homedir = "/tmp/"
        self.gpg = gnupg.GPG(homedir=kernsign.homedir)
        self.kpath = kernsign.homedir + "kernel"
        self.ipath = kernsign.homedir + "init"
        kernel = open(self.kpath, "wb")
        init = open(self.ipath, "wb")
        init.write(self.data)
        kernel.write(self.data)
        init.close()
        kernel.close()

    # Test the key generation procedure
    def test_generate_key(self):
        self.assertIsNotNone(kernsign.gen_key(self.gpg, 'RSA', 1024))
        self.assertIsNone(kernsign.gen_key(self.gpg, 'bullshit', 433))

    # Test for signature update
    def test_update_sigs(self):
        self.assertTrue(kernsign.update_sigs(self.gpg, self.kpath, self.ipath,
                                             kernsign.homedir))
        kfile = open(self.kpath + ".asc")
        ifile = open(self.ipath + ".asc")
        self.assertIsNotNone(kfile)
        self.assertIsNotNone(ifile)
        kfile.close()
        ifile.close()

    def test_check_signatures(self):
        pass

    def test_homedir(self):
        pass

    def test_no_gpg(self):
        pass

if __name__ == '__main__':
    unittest.main()
