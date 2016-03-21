""" asterix/mycard.py

__author__ = "Petr Tobiska"

Author: Petr Tobiska, mailto:petr.tobiska@gmail.com, petr.tobiska@gemalto.com
Date: 2015-11-16

This file is part of asterix, a framework for  communication with smartcards
 based on pyscard. This file implementes helpful functions for card
 communication.

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
"""

import sys
import re
from binascii import hexlify, unhexlify
from struct import pack
import time
# pyscard
from smartcard.System import readers
from smartcard.CardConnectionObserver import CardConnectionObserver
from smartcard.CardConnectionDecorator import CardConnectionDecorator
import smartcard.scard as scard
from smartcard.pcsc.PCSCExceptions import *
# asterix
from formutil import l2s, s2l
from GAF import *
__all__ = ( 'dispTime', 'ISOException', 'connectCard', 'resetCard' )

def getTime():
    """ Get current time in ms."""
    pf = sys.platform
    if pf == 'win32':
        return 1000. * time.clock()
    elif pf == 'linux2':
        return 1000. * time.time()
    else:
        raise RuntimeError, "getTime() not implemented for platform %s" % pf

def dispTime( c, zOn = True ):
    """ For CardConnection or derived object <c> set Displaying elapsed time
on/off (zOn = True/False) """
    while isinstance( c, smartcard.CardConnectionDecorator.
                      CardConnectionDecorator ):
        c = c.component
    if not isinstance( c, smartcard.pcsc.PCSCCardConnection.
                       PCSCCardConnection ):
        raise RuntimeError, "dispTime( c, zOn = True ) expects " +\
            "PCSCCardConnection or CardConnectionDecorator as c"
    c.zTime = zOn
    
class ISOException( Exception ):
    def __init__( self, sw ):
        self.sw = sw
    def __str__( self ):
        return "ISOException SW %04X" % self.sw

class ConsoleObserver( CardConnectionObserver ):
    def update( self, cardconnection, event ):
        zTime = cardconnection.__dict__.get( 'zTime', False )
        if event.type == 'connect':
            print 'Connecting to ' + cardconnection.getReader()
        elif event.type == 'disconnect':
            print 'Disconnecting from ' + cardconnection.getReader()
        elif event.type == 'command':
            apdubytes = [ chr( x ) for x in event.args[0] ]
            apdu = hexlify( ''.join( apdubytes )).upper()
            print " => %s %s %s %s" % ( apdu[0:4], apdu[4:8],
                                        apdu[8:10], apdu[10:] )
            dir( cardconnection )
            if zTime:
                self.t1 = getTime()
        elif event.type == 'response':
            sw = "%02X%02X" % tuple( event.args[1:] )
            respdata = ''.join( [ "%02X" % x for x in event.args[0] ]) + \
                       ( len( event.args[0] ) > 0 and " " or "" )
            print " <= " + respdata + sw
            if zTime:
                print "time: %.4f ms" % ( getTime() - self.t1 )
        else: print event.type

class GAFConnection( CardConnectionDecorator ):
    """ Enhance CardConnection by GAF processor """
    def __init__( self, connection, **kw ):
        self.objects = kw
        self.connection = connection
        CardConnectionDecorator.__init__( self, connection )
    def send( self, templ, **kw ):
        """ Evaluate GAF and transmit as APDU
templ   - a GAF template to evaluate
kw      - GAF dictionary (updates dictionary from GAFConnection.__init__)
Return ( resp, SW ) as ( str, int )"""
        objects = self.objects.copy()
        objects.update( kw )
        sapdu = GAF( templ ).eval( **objects )
        apdu = s2l( sapdu )
        assert 5 <= len( apdu ) and len( apdu ) <= 260,\
            "Wrong APDU length %d, '%s'" % ( len(apdu), hexlify( sapdu ))
        resp, sw1, sw2 = CardConnectionDecorator.transmit( self, apdu )
        if sw1 == 0x6C and len( apdu ) == 5:
            apdu[4] = sw2
            resp, sw1, sw2 = CardConnectionDecorator.transmit( self, apdu )
        elif sw1 == 0x61:
            apdu = [ 0, 0xC0, 0, 0, sw2 ]
            resp, sw1, sw2 = CardConnectionDecorator.transmit( self, apdu )
        sw = ( sw1 << 8 ) + sw2
        return l2s( resp ), sw

def connectCard( reader_name = '' ):
    r = readers()
    rege = re.compile( r'.*'+reader_name+r'.*' )
    cons = [ rr for rr in r if  rege.match( rr.__str__()) ]
    if( len( cons ) != 1 ):
        print "Non uniq connections:", cons
        return
    c = GAFConnection( cons[0].createConnection())
    observer = ConsoleObserver()
    c.addObserver( observer )
    dispTime( c, False ) # default: time not printed
    c.connect()
    return c

def resetCard( c, zReconnect = True ):
    hresult, hcontext = scard.SCardEstablishContext(scard.SCARD_SCOPE_USER)
    if hresult != scard.SCARD_S_SUCCESS:
        raise EstablishContextException(hresult)

    # hresult, readers = scard.SCardListReaders(hcontext, [])
    # if hresult != scard.SCARD_S_SUCCESS:
    #     raise ListReadersException(hresult)
    # print 'PC/SC Readers:', readers

    reader_name = c.getReader()
    # print "Using reader:", reader_name

    # Connect in SCARD_SHARE_SHARED mode
    hresult, hcard, dwActiveProtocol = scard.SCardConnect(hcontext,
        reader_name, scard.SCARD_SHARE_SHARED, scard.SCARD_PROTOCOL_ANY)
    if hresult != scard.SCARD_S_SUCCESS:
        raise BaseSCardException(hresult)

    if zReconnect:
        print "Reset reader '%s' using SCardReconnect" % reader_name

        # Reconnect after reset
        # hresult, dwActiveProtocol = SCardReconnect(hcard,
        #     SCARD_SHARE_EXCLUSIVE, SCARD_PROTOCOL_ANY, SCARD_RESET_CARD)
        hresult, dwActiveProtocol = scard.SCardReconnect(hcard,
            scard.SCARD_SHARE_SHARED, scard.SCARD_PROTOCOL_ANY,
            scard.SCARD_RESET_CARD)
        if hresult != scard.SCARD_S_SUCCESS:
            raise BaseSCardException(hresult)
    else:
        print "Reset reader '%s' using SCardDisconnect" % reader_name

        # Disconnect after reset
        hresult = scard.SCardDisconnect(hcard, scard.SCARD_RESET_CARD)
        if hresult != scard.SCARD_S_SUCCESS:
            raise BaseSCardException(hresult)

    hresult = scard.SCardReleaseContext(hcontext)
    if hresult != scard.SCARD_S_SUCCESS:
        raise ReleaseContextException(hresult)

    if zReconnect: c.connect()

