#!/usr/bin/env python3

import sys
import socket
import unittest
from utils.dns_utils import DNS_Request, DNS_Response
from utils.network import resolve_domain_name


# should be set by test_entry
dnsIP = None
dnsPort = None


class TestDNS(unittest.TestCase):

    def resolveDomain(self, domain_name):
        global dnsIP, dnsPort
        return resolve_domain_name(domain_name, dnsIP, dnsPort)

    def test_non_exist(self):
        res = self.resolveDomain("domain.non.exists")
        self.assertEqual(res, None)

    def test_cname1(self):
        res = self.resolveDomain("cn-lab.nasa.nju.edu.cn.")
        self.assertEqual(res.response_type, 5)
        self.assertEqual(str(res.response_val), "bsy.nasa.nju.edu.cn.")

    def test_cname2(self):
        res = self.resolveDomain("1.108.nasa.nju.edu.cn")
        self.assertEqual(res.response_type, 5)
        self.assertEqual(str(res.response_val), "nasa.nju.edu.cn.")

    def test_location1(self):
        res = self.resolveDomain("bsy.nasa.nju.edu.cn.")
        self.assertEqual(res.response_type, 1)
        self.assertEqual(str(res.response_val), "114.212.81.125")

    def test_location2(self):
        res = self.resolveDomain("nasa.nju.edu.cn.")
        self.assertEqual(res.response_type, 1)
        self.assertIn(str(res.response_val), ["210.28.132.191", "114.212.80.252"])


if __name__ == '__main__':
    unittest.main()
