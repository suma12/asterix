asterix, a framework for communication with smartcards based on pyscard
===============================================================================
https://github.com/suma12/asterix
-------------------------------------------------------------------------------

Author: Petr Tobiska, mailto:petr.tobiska@gmail.com,
	              mailto:petr.tobiska@gemalto.com

This file is a part of asterix, a framework for communication with smartcards
based on pyscard.

asterix is free software; you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation; either version 2.1 of the License, or
(at your option) any later version.

asterix is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with pyscard; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

-------------------------------------------------------------------------------
Last update : asterix 0.2 (December 2015)
-------------------------------------------------------------------------------

asterix is a framework for communication with smartcards based on pyscard

It consists of:

**formutil**
  a module with formatting utilities

**GAF**
  a module for representation and evaluation of ASN1 structures

**mycard**
  a module providing handy primitives for card communication

**APDU**
  a module for creation and transmission of common APDU to a smartcard

**SCP02**
  an implementation of Secure Channel Protocol 02 as defined in
  Global platform

**SCP03**
  an implementation of Secure Channel Protocol 03 as defined in
  Global platform

**applet**
  a module for loading, installation and deletion of JavaCard
  applets to a smartcard
  
**CAT**
  a module implementing Card Application Toolkit as defined in
  ETSI TS 102.223

**SecurePacket**
  a module implementing Secure Packet for OTA communication
  with smartcards

All modules are platform independent, working with Python 2.7

All modules relies on pyscard, a package implementing PCSC layer for
communication with smartcards.

-------------------------------------------------------------------------------
Documentation
-------------------------------------------------------------------------------

See [wiki](https://github.com/suma12/asterix/wiki)

-------------------------------------------------------------------------------
Installation
-------------------------------------------------------------------------------

The asterix framework is packaged using the standard distutils python
module. It is pure python implementation.

Installing from .msi:
---------------------

Run provided installer.

Installing using distutils:
---------------------------

Run
python setup.py install

-------------------------------------------------------------------------------
Dependencies
-------------------------------------------------------------------------------

The asterix framework depends on the following packages:
 - pyscard >= 1.6.16
 - PyCrypto >= 2.6.1
