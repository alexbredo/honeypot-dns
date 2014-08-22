#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2014 Alexander Bredo
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or 
# without modification, are permitted provided that the 
# following conditions are met:
# 
# 1. Redistributions of source code must retain the above 
# copyright notice, this list of conditions and the following 
# disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above 
# copyright notice, this list of conditions and the following 
# disclaimer in the documentation and/or other materials 
# provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND 
# CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR 
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE 
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR 
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF 
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT 
# OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
# POSSIBILITY OF SUCH DAMAGE.


'''
TODO: 
 - kleinen Cache implementieren, der sich für wenige Minuten die Zuordnung merkt
 - Evtl. auf einige Anfragen als nicht existent antworten (Realismus)
 - Evtl. nach einer besseren Alternative zu twisted suchen. Diese Twisted-Implementierung ist eklig (defereds & co). 
'''

import random, time
from twisted.internet import reactor, defer
from twisted.names import dns
from twisted.names import client, server
from twisted.names.common import ResolverBase

from base.applog import *
from base.appconfig import Configuration
from handler.manager import HandlerManager
from bredo.network import Network

class DNSConfig(Configuration):
	def setup(self, *args, **kwargs): # Defaults: 
		self.__version = '0.1.0'
		self.__appname = 'honeypot_dns'
		self.port=53
		self.domain='services.example.com'
		self.mode = 'random' # fixed, random
		self.ipv4_fixed=['192.168.1.2']
		self.ipv6_fixed=['::1']
		self.domain_gen_bucket = [ 
			["eu", "us", "cn", "br", "ru"],                 # locations
			["north", "east", "south", "west", "central"],  # cardinal directions
			["aws", "smb", "dc", "fs", "sip"],              # services
			range(1,9),                                     # counter
			["srvpool", "client", "it", "head"],            # pools or departments
			["example.com", "sample.com"]                   # domain
		]
		self.enabled_handlers = {
			'elasticsearch': True, 
			'screen': True,
			'file': True
		}
		self.elasticsearch = {
			'host': '127.0.0.1', 
			'port': 9200, 
			'index': 'honeypot'
		}
		self.filename = 'honeypot_output.txt'
		
config = DNSConfig()
handler = HandlerManager(config)

if config.mode == 'fixed':
	if len(config.ipv4_fixed) == 0:
		log.error('Fixed DNS-Mode enabled, but no IPv4-Addresses defined.')
	if len(config.ipv6_fixed) == 0:
		log.error('Fixed DNS-Mode enabled, but no IPv6-Addresses defined.')
	
clientaddr = None
srvaddr = Network().getMyOwnIP()

class ObfuscateResolver(ResolverBase):
	def _lookup(self, name, cls, qtype, timeout):
		if qtype == 12: # Reverse Query:
			hostname = self.__getRandomName()
			ip = '.'.join(reversed(name[:-13].split('.')))
			self.__logInfo('Reverse-Query', "%s --> %s" % (ip, hostname), True)
			rr = dns.RRHeader(name=name, type=qtype, cls=cls, ttl=60, payload=dns.Record_PTR(name=hostname, ttl=60))
			results = [rr]
			authority = addtional = []
			return defer.succeed((results, authority, addtional))
	
	def lookupAddress(self, name, timeout=60):
		ip = self.__getIPv4()
		self.__logInfo('IPv4-Query', "%s --> %s" % (name, ip), True)
		#name = self.__replaceDomain(name)
		rr = dns.RRHeader(name=name, type=dns.A, ttl=60, payload=dns.Record_A(address=ip, ttl=60))
		results = [rr]
		authority = []
		addtional = []
		return defer.succeed((results, authority, addtional))
		
	def lookupIPV6Address(self, name, timeout=60):
		ip = self.__getIPv6()
		self.__logInfo('IPv6-Query', "%s --> %s" % (name, ip), True)
		#name = self.__replaceDomain(name)
		rr = dns.RRHeader(name=name, type=dns.AAAA, ttl=60, payload=dns.Record_AAAA(address=ip, ttl=60))
		results = [rr]
		authority = addtional = []
		return defer.succeed((results, authority, addtional))
		
	def __replaceDomain(self, fqdn):
		return "%s.%s" % (fqdn[:fqdn.find('.')], config.domain)
		
	def __getIPv4(self):
		if config.mode.lower() == 'fixed':
			id = random.randint(0, len(config.ipv4_fixed) - 1)
			return config.ipv4_fixed[id]
		else:
			return self.__getRandomIPv4()
		
	def __getIPv6(self):
		if config.mode.lower() == 'fixed':
			id = random.randint(0, len(config.ipv6_fixed) - 1)
			return config.ipv6_fixed[id]
		else:
			return self.__getRandomIPv6()

	def __getRandomIPv4(self):
		return '.'.join([str(random.randint(1, 254)) for x in range(0,4)])
		
	def __getRandomIPv6(self):
		return ':'.join([str(hex(random.randint(1, 65535)).rstrip("L").lstrip("0x") or "0") for x in range(0,8)])
		
	def __getRandomName(self):
		return "%s-%s-%s%s.%s.%s" % tuple(group[random.randint(0, len(group) - 1)] for group in config.domain_gen_bucket)
	
	def __logInfo(self, type, command, successful):
		data = {
			'module': 'DNS', 
			'@timestamp': int(time.time() * 1000), # in milliseconds
			'sourceIPv4Address': clientaddr[0], 
			'sourceTransportPort': clientaddr[1],
			'destinationIPv4Address': srvaddr,
			'destinationTransportPort': config.port,
			'type': type,
			'command': command, 
			'success': successful
		}
		handler.handle(data)
		
		
class MyDNSDatagramProtocol(dns.DNSDatagramProtocol):
	def datagramReceived(self, data, addr):
		global clientaddr
		clientaddr = addr
		return super(MyDNSDatagramProtocol, self).datagramReceived(data, addr)

def main():
	resolver = ObfuscateResolver()
	#resolver = Resolver(servers=[('8.8.8.8', 53)])
	#resolver = client.createResolver(hosts='hosts.txt')

	factory = server.DNSServerFactory(clients=[resolver])
	protocol = MyDNSDatagramProtocol(factory)

	reactor.listenUDP(config.port, protocol)
	reactor.listenTCP(config.port, factory)
	log.info("Server listening on port %s." % config.port)
	reactor.run()

if __name__ == '__main__':
	main()