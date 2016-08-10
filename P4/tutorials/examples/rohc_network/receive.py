#!/usr/bin/python

# Copyright 2013-present Barefoot Networks, Inc. 
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from scapy.all import *
import sys
from struct import *
import threading 

class Receiver(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def received(self, p):
        print "Received packet"
        hexdump(p)
        print "End packet\n"
	sys.exit(0)

    def run(self):
				sniff(iface="eth0", prn=lambda x: self.received(x))

def main():
        Receiver().start()

if __name__ == '__main__':
    main()
