""" asterix/APDU.py

__author__ = "Petr Tobiska"

Author: Petr Tobiska, mailto:petr.tobiska@gmail.com

This file is part of asterix, a framework for  communication with smartcards
 based on pyscard. This file implements handfull APDU commands.

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

References:
[GP CS] GlobalPlatform Card Specification, Version 2.2.1, Jan 2011
[GP AmD] Secure Channel Protocol 03, Card Specification v 2.2 - Amendment D,
         Version 1.1, Sep 2009

"""

import re
import hashlib
import random
from struct import pack, unpack
from binascii import hexlify, unhexlify
# PyCrypto
from Crypto.Cipher import DES, DES3, AES
# ECSDA
from ecdsa import ecdsa, ellipticcurve
# pyscard
from smartcard.ATR import ATR
# asterix
from formutil import s2l, l2s, derLen, derLV, s2int, int2s, s2ECP, chunks,\
    split2TLV, findTLValue, swapNibbles
from GAF import GAF
from applet import DESsign
from SCP03 import CMAC
from mycard import ISOException, resetCard
__all__ = ('calcKCV', 'putKey', 'storeDataPutKey',
           'push2B_DGI', 'X963keyDerivation', 'Push3scenario',
           'selectApplet', 'openLogCh', 'closeLogCh',
           'getStatus', 'getExtCardRes', 'getData',
           'selectFile', 'readBinary', 'readRecord',
           'updateBinary', 'updateRecord',
           'verifyPin', 'changePin', 'disablePin', 'enablePin', 'unblockPin',
           'selectUSIM', 'cardInfo', 'KeyType')

INS_VERIFY_PIN   = 0x20
INS_CHANGE_PIN   = 0x24
INS_DISABLE_PIN  = 0x26
INS_ENABLE_PIN   = 0x28
INS_UNBLOCK_PIN  = 0x2C
INS_MANAGE_LOGCH = 0x70
INS_SELECT       = 0xA4
INS_READBIN      = 0xB0
INS_READREC      = 0xB2
INS_GETDATA      = 0xCA    
INS_UPDBIN       = 0xD6
INS_UPDREC       = 0xDC
INS_PUTKEY       = 0xD8
INS_STOREDATA    = 0xE2
INS_GETSTATUS    = 0xF2


class KeyType:
    """Key types as defined in [GP CS] Tab 11.16"""
    # subset of currently supported keys
    DES_IMPLICIT = 0x80
    TDES_CBC     = 0x82
    DES_ECB      = 0x83
    DES_CBC      = 0x84
    AES          = 0x88


def calcKCV(keyValue, zAES=False):
    """Calculate KCV for symmetric key.
keyValue - key values as string (DES, 3DES2k, 3DES3k, AES)
zAES     - True if key is AES (i.e. encrypt block of '01' instead of '00')

Return 3B-long string."""
    if zAES:
        assert len(keyValue) in (16, 24, 32), "Wrong length of AES key"
        block = '\x01'*16
        tkey = AES.new(keyValue, AES.MODE_ECB)
    else:
        assert len(keyValue) in (8, 16, 24), "Wrong length of (3)DES key"
        block = '\x00'*8
        if len(keyValue) == 8:
            tkey = DES.new(keyValue, DES.MODE_ECB)
        else:
            tkey = DES3.new(keyValue, DES.MODE_ECB)
    return tkey.encrypt(block)[:3]


def putKey(oldKeyVersion, newKeyVersion, keyId, keyComponents,
           zMoreCmd=False, zMultiKey=False, keyDEK=None,
           lenMAC=8):
    """Build APDU for PUT KEY command.
oldKeyVersion - key version to be replaced. If zero, new key is created.
newKeyVersion - key version of key being put
keyId         - id of the 1st key being put
keyComponents - list of key components being put.
                Each componet is a tuple of key type (u8) and value (string).
zMoreCmd      - P1.b8, signals if there is more commands
zMultiKey     - P2.b8, signals if more than one component being put
keyDEK        - KIK or DEK key. keyDEK.encrypt(data) called to encrypt
                (including padding) key component value if not None.
                If has attribute zAES and keyDEK.zAES evaluates as True, it is
                considered as AES key and [GP AmD] 7.2 formatting is used.
lenMAC        - length of CMAC for AES.
                Applicable if AES key with key id=0x02 (KID) and
                key version 0x01-0x0F or 0x11 is being put with AES keyDEK
                (see ETSI 102.226 rel 9+, 8.2.1.5)

Returns APDU built (as list of u8).

See [GP CS] 11.8 and [GP AmD] 7.2 for reference.
See [GP CS] Tab 11.16 for coding of key type.
Currently only Format1 supported.
"""
    # sanity check
    assert 0 <= oldKeyVersion < 0x80
    assert 0 < newKeyVersion < 0x80
    assert 0 < keyId < 0x80
    assert len(keyComponents) > 0
    assert lenMAC in (4, 8)

    P1 = (zMoreCmd and 0x80 or 0) | oldKeyVersion
    P2 = (zMultiKey and 0x80 or 0) | keyId

    data = chr(newKeyVersion)
    for kc in keyComponents:
        keyType, keyVal = kc[:2]  # ignore eventual keyUsage and keyAccess
        assert 0 <= keyType < 0xFF
        if keyDEK:
            encValue = keyDEK.encrypt(keyVal)
            # for AES as keyDEK, prepend length of component
            if 'zAES' in dir(keyDEK) and keyDEK.zAES:
                encValue = derLen(keyVal) + encValue
                # see ETSI 102.226 rel 9+, 8.2.1.5
                if keyType == KeyType.AES and keyId == 2 and \
                   newKeyVersion in range(0x01, 0x10) + [0x11]:
                    encValue += chr(lenMAC)
        else:
            encValue = keyVal
        # calculate KCV
        if keyType in (KeyType.DES_IMPLICIT, KeyType.TDES_CBC,
                       KeyType.DES_ECB, KeyType.DES_CBC, KeyType.AES):
            kcv = calcKCV(keyVal, keyType == KeyType.AES)
        else:
            kcv = ''

        data += chr(keyType) + derLen(encValue) + encValue + derLen(kcv) + kcv
        keyId += 1

    apdu = [0x80, INS_PUTKEY, P1, P2, len(data)] + s2l(data)
    return apdu


def push2B_DGI(keyVer, keys, keyCASDenc):
    """ Create DGI 00A6 and 8010 for Push2B scenario
keyVer     - key verions (u8)
keys       - ((keytype, keyvalue)); 1 or 3 sym. keys
keyCASDenc - a method to call for encryption 8010 content
Return DGIs built (as list of strings)."""
    # DGI tag on 2B (GP Card Spec 2.2.1, 11.1.12)
    # DGI length coding as in GP Systems Scripting Language Spec. v1.1.0, an. B
    # i.e. on 1B for x < 255, FF<yyyy> for x >=255
    KAT = GAF(""" -- Control Reference Template (KAT)
    -- see GP 2.2.1 AmA 4.4
    00A6 #[
        A6 #(
          90 #(04)        -- scenario identifier: Push#2B
          95 #($keyUsage)
          80 #($keyType)
          81 #($keyLen)
          83 #($keyVer)
        --  45 #($SDIN) -- optional Security Domain Image Number
   )] """)
    assert len(keys) in (1, 3), "One or three sym. keys expected"
    keyUsage = len(keys) == 1 and '\x5C' or '\x10'  # Tab. 13
    keyType = keys[0][0]
    assert all([k[0] == keyType for k in keys]), "Key types differ"
    # remap keyType to '80' as required by GP UICC config 10.3.1
    if keyType in (KeyType.TDES_CBC, KeyType.DES_ECB, KeyType.DES_CBC):
        keyType = KeyType.DES_IMPLICIT
    lens = [len(k[1]) for k in keys]
    l = max(lens)
    assert l == min(lens), "Key lengths differ"
    dgi00A6 = KAT.eval(keyUsage=keyUsage, keyType=chr(keyType),
                       keyLen=chr(l), keyVer=chr(keyVer))
    data = keyCASDenc(''.join([k[1] for k in keys]))
    dgi8010 = pack(">H", 0x8010) + chr(len(data)) + data
    return (dgi00A6, dgi8010)


def storeDataPutKeyDGI(keyVer, keyComponents, keyId=1, keyDEK=None):
    """Build DGI for Store Data for Put Key.
keyVer        - key version of key being created
keyComponents - list of key components being put.
                Each componet is a tuple of key type (u8), value (string)
                and optionally Key Usage Qualifier and Key Access
                (u8, defaults 0x18, 0x14 or 0x48 for key UQ, 0x00 for key ac.)
keyId         - id of the 1st key being created (optional, u8, default 1)
keyDEK        - KIK or DEK key. keyDEK.encrypt(data) called to encrypt
                (including padding) key component value if not None.
                If has attribute zAES and keyDEK.zAES evaluates as True, it is
                considered as AES key and [GP AmD] 7.2 formatting is used.

Returns DGIs built (as list of string).
See GP 2.2.1 AmA 4.10.2 for reference.
"""
    # sanity check
    assert 0 < keyVer and keyVer < 0x80
    assert 0 < keyId and keyId < 0x80
    assert len(keyComponents) > 0

    KeyUQ = (None, 0x38, 0x34, 0xC8)  # see GP 2.2.1, 11.1.9
    templ = """ B9 #(95#($keyUQ) 96#($keyAc) 80#($keyType) 81#($keyLen)
                82#($keyId) 83#($keyVer) 84#($KCV))"""
    d = {'keyVer': chr(keyVer)}
    B9 = ''
    dgi8113 = []
    for kc in keyComponents:
        assert len(kc) in (2, 4), "wrong keyComponent" + kc.__str__()
        if len(kc) == 2:
            keyType, keyVal = kc
            keyUQ = 1 <= keyId <= 3 and KeyUQ[keyId] or 0xFF
            keyAc = 0x00
        else:
            keyType, keyVal, keyUQ, keyAc = kc
        d['keyLen'] = chr(len(keyVal))
        assert 0 <= keyType < 0xFF
        if keyType in (KeyType.DES_IMPLICIT, KeyType.TDES_CBC,
                       KeyType.DES_ECB, KeyType.DES_CBC, KeyType.AES):
            d['KCV'] = calcKCV(keyVal, keyType == KeyType.AES)
        else:
            d['KCV'] = ''
        d['keyId'] = chr(keyId)
        for k in ('keyType', 'keyUQ', 'keyAc', 'keyId'):
            d[k] = chr(locals()[k])
        tlv = GAF(templ).eval(**d)
        if keyDEK:
            encValue = keyDEK.encrypt(keyVal)
        else:
            encValue = keyVal
        B9 += tlv
        dgi8113.append(pack(">HB", 0x8113, len(encValue)) + encValue)
        keyId += 1
    return(pack(">HB", 0x00B9, len(B9)) + B9, dgi8113)


def storeDataPutKey(keyVer, keyComponents, keyId=1, keyDEK=None):
    """Build APDU for Store Data for Put Key.
keyVer, keyComponents, keyId and keyDEK as in storeDataPutKeyDGI.
Return APDU a u8 list."""
    dgi00B9, dgi8113 = storeDataPutKeyDGI(keyVer, keyComponents,
                                          keyId, keyDEK)
    data = dgi00B9 + ''.join(dgi8113)
    assert len(data) < 256, "Longer Put Key not implemented"
    P1 = 0x88
    P2 = 0
    apdu = [0x80, INS_STOREDATA, P1, P2, len(data)] + s2l(data)
    return apdu

# ###### Scenario 3 stuff
# Preloaded ECC Curve Parameters, GP 2.2.1 AmE 4.5
# N.B., all have cofactor = 1
ECC_Curves = {
    0x00: ecdsa.generator_256,  # NIST P-256
    0x01: ecdsa.generator_384,  # NIST P-384
    0x02: ecdsa.generator_521,  # NIST P-521
    # 0x03: brainpoolP256r1,
    # 0x04: brainpoolP256t1,
    # 0x05: brainpoolP384r1,
    # 0x06: brainpoolP384t1,
    # 0x07: brainpoolP512r1,
    # 0x08: brainpoolP512t1,
}

# tag definition
T_IIN        = 0x42
T_SDIN = T_CIN = 0x45
T_keyType    = 0x80
T_keyLen     = 0x81
T_keyID      = 0x82
T_keyVer     = 0x83
T_DR         = 0x85
T_HostID     = 0x84
T_receipt    = 0x86
T_scenarioID = 0x90
T_seqCounter = 0x91
T_keyUsage   = 0x95
T_keyAcc     = 0x96
T_CRT        = 0xA6


def X963keyDerivation(sharedSecret, bytelen, sharedInfo='',
                      h = hashlib.sha256):
    """ X9.63 Key Derivation Function as deifned in TR-03111 4.3.3
bytelen      - expected length of Key Data
sharedSecret, sharedInfo - strings
h            - function to create HASH object (default hashlib.sha256)
Return Key Data (string)
Reference: TR-03111: BSI TR-03111 Elliptic Curve Cryptography, Version 2.0
   https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03111/BSI-TR-03111_pdf.html"""
    keyData = ''
    l = h().digest_size
    j = (bytelen - 1)/l + 1
    for i in xrange(1, 1+j):
        keyData += h(sharedSecret + pack(">L", i) + sharedInfo).digest()
    return keyData[:bytelen]


def DESMAC(key, data):
    """ Calculate MAC single DES with final 3DES"""
    return DESsign(key).calc(data)

ktDES = KeyType.DES_IMPLICIT
ktAES = KeyType.AES


class Push3scenario:
    """ Implementation of Global Platform Push #3 scenario (ECKA)"""
    def __init__(self, keyParRef, pkCASD, **kw):
        """ Constructor
keyParRef - Key Parameter Reference
pkCASD    - PK.CASD.ECKA (tuple long x, long y)
optional **kw: IIN, CIN (as strings)"""
        assert keyParRef in ECC_Curves, \
            "Unknown Key param reference 0x%02X" % keyParRef
        self.keyParRef = keyParRef
        self.generator = ECC_Curves[keyParRef]
        self.curve = self.generator.curve()
        self.bytelen = len(int2s(self.curve.p()))
        assert self.bytelen in (32, 48, 64, 66)  # currently allowed keys
        pkCASDxy = s2ECP(pkCASD)
        assert self.curve.contains_point(*pkCASDxy),\
            "PK.CASD.ECKA not on the curve"
        self.pkCASD = ellipticcurve.Point(self.curve, *pkCASDxy)
        for k in ('IIN', 'CIN'):
            if k in kw:
                assert isinstance(kw[k], str)
                self.__dict__[k] = kw[k]

    def makeDGI(self, keyVer, privkey=None,
                keys=([(KeyType.AES, 16)]*3),
                zDelete=False, zDR=False, zID=False, **kw):
        """ Prepare data for Push #3 scenario and generate keys.
keyVer     - key version to create
privkey    - eSK.AP.ECKA (secret multiplier as string)
             randomly generated if None
keys       - [(keyType, keyLen)] to generate
zDelete, zDR, zID - bits 1-3 of Parameters of scenario, (GP AmE, Tab. 4-17)
optional **kw: keyId, seqCounter, SDIN, HostID
Return <data for StoreData>"""
        if privkey is None:
            secexp = random.randrange(2, self.generator.order())
        else:
            secexp = s2int(privkey)
            assert 1 < secexp < self.generator.order(), "Wrong eSK.AP.ECKA"
        print "eSK.AP.ECKA = %X" % secexp
        pubkey = self.generator * secexp
        dgi7F49 = pack(">HBB", 0x7F49, 2*self.bytelen+1, 4) + \
            int2s(pubkey.x(), self.bytelen * 8) + \
            int2s(pubkey.y(), self.bytelen * 8)
        # calculate Shared Secret, suppose that cofactor is 1
        S_AB = secexp * self.pkCASD
        self.sharedSecret = int2s(S_AB.x(), self.bytelen * 8)
        print "Shared Secret =", hexlify(self.sharedSecret).upper()
        # build DGI 00A6
        if zID:
            assert hasattr(self, 'IIN'), "Missing IIN while CardId requested"
            assert hasattr(self, 'CIN'), "Missing cIN while CardId requested"
            assert 'HostID' in kw and isinstance(kw['HostID'], str)
            self.HostCardID = ''.join([derLV(v) for v in
                                       (kw['HostID'], self.IIN, self.CIN)])
        else:
            self.HostCardID = ''
        self.zDR = zDR
        scenarioPar = (zDelete and 1 or 0) +\
                      (zDR and 2 or 0) +\
                      (zID and 4 or 0)
        assert all([k[0] in (KeyType.DES_IMPLICIT, KeyType.AES) for k in keys])
        ktl1 = keys[0]
        zDifKey = any([keys[i] != ktl1 for i in xrange(1, len(keys))])
        tA6value = pack("BBBB", T_scenarioID, 2, 3, scenarioPar)
        if zDifKey:
            self.receiptAlgo = CMAC
            self.keyLens = [16] + [k[1] for k in keys]
            self.keyDesc = ''
            if 'keyId' in kw:
                tA6value += pack("BBB", T_keyID, 1, kw['keyId'])
            tA6value += pack("BBB", T_keyVer, 1, keyVer)
            # default keyUsage from GP 2.2.1 AmE tab. 4-16 for ENC, MAC, DEK
            for k, keyUsage in zip(keys, (0x38, 0x34, 0xC8)):
                if len(k) > 2:
                    keyUsage = k[2]
                tB9value = pack("BBB", T_keyUsage, 1, keyUsage)
                if len(k) >= 4:  # optional key Access as fourth elem. of key
                    tB9value += pack("BBB", T_keyAcc, 1, k[3])
                tB9value += pack("BBB", T_keyType, 1, k[0])
                tB9value += pack("BBB", T_keyLen, 1, k[1])
                self.keyDesc += pack("BBB", keyUsage, *k[:2])
                tA6value += '\xB9' + derLV(tB9value)
        else:
            assert len(keys) in (1, 3), \
                "One or three secure ch. keys expected."
            self.keyLens = [ktl1[1]] * (1 + len(keys))
            self.receiptAlgo = ktl1[0] == KeyType.AES and CMAC or DESMAC
            keyUsage = len(keys) == 1 and 0x5C or 0x10
            self.keyDesc = pack("BBB", keyUsage, *ktl1[:2])
            tA6value += pack("BBB", T_keyUsage, 1, keyUsage)
            if len(ktl1) == 4:
                tA6value += pack("BBB", T_keyAcc, 1, ktl1[3])
            tA6value += pack("BBB", T_keyType, 1, ktl1[0])
            tA6value += pack("BBB", T_keyLen, 1, ktl1[1])
            if 'keyId' in kw:
                tA6value += pack("BBB", T_keyID, 1, kw['keyId'])
            tA6value += pack("BBB", T_keyVer, 1, keyVer)
        if 'seqCounter' in kw:
            tA6value += chr(T_seqCounter) + derLV(kw['seqCounter'])
        if 'SDIN' in kw:
            tA6value += chr(T_SDIN) + derLV(kw['SDIN'])
        if zID:
            tA6value += chr(T_HostID) + derLV(kw['HostID'])
        self.tA6 = chr(T_CRT) + derLV(tA6value)
        dgi00A6 = pack(">HB", 0x00A6, len(self.tA6)) + self.tA6
        return (dgi00A6, dgi7F49)

    def generKeys(self, respData):
        """ Verify receipt and generate symmetric keys.
respData - response to Store Data (string)
Return generated keys (tuple of strings)"""
        try:
            data2rec = self.tA6
        except KeyError:
            print "Run makeDGI first"
            return
        respTLV = split2TLV(respData)
        if self.zDR:
            lenDR = (self.bytelen // 32) * 16  # map to 16, 24 or 32
            DR = respTLV[0][1]
            assert len(respTLV) == 2 and \
                respTLV[0][0] == T_DR and len(DR) == lenDR
            data2rec += pack("BB", T_DR, lenDR) + DR
        else:
            assert len(respTLV) == 1
        assert respTLV[-1][0] == T_receipt
        receipt = respTLV[-1][1]

        sharedInfo = self.keyDesc
        if self.zDR:
            sharedInfo += DR
        if hasattr(self, 'HostCardID'):
            sharedInfo += self.HostCardID
        print "Shared Info =", hexlify(sharedInfo).upper()

        keyData = X963keyDerivation(self.sharedSecret, sum(self.keyLens),
                                    sharedInfo)
        keyDataIt = chunks(keyData, self.keyLens)
        receiptKey = keyDataIt.next()
        print "Receipt Key =", hexlify(receiptKey).upper()
        expReceipt = self.receiptAlgo(receiptKey, data2rec)
        assert receipt == expReceipt, "Receipt verification failed"
        return [k for k in keyDataIt if k]  # skip empty rest


def selectApplet(c, AID, logCh=0):
    """ Select applet on a given logical channel or
open new log. channel if logCh is None. """
    if logCh is None:
        logCh = openLogCh(c)
    # select the Applet on the given logical channel
    apdu = [logCh, INS_SELECT, 4, 0, len(AID)] + s2l(AID)
    resp, sw1, sw2 = c.transmit(apdu)
    if sw1 == 0x6C and len(AID) == 0:
        apdu = [logCh, INS_SELECT, 4, 0, sw2]
        resp, sw1, sw2 = c.transmit(apdu)
    if(sw1 == 0x61):
        apdu = [logCh, 0xC0, 0, 0, sw2]
        resp, sw1, sw2 = c.transmit(apdu)
    sw = (sw1 << 8) + sw2
    if sw != 0x9000:
        raise ISOException(sw)
    respdata = l2s(resp)
    # close channel
    return (respdata, logCh)


def openLogCh(c):
    """ Manage channel to open logical channel. """
    apdu = [0, INS_MANAGE_LOGCH, 0, 0, 1]
    resp, sw1, sw2 = c.transmit(apdu)
    sw = (sw1 << 8) + sw2
    if sw != 0x9000:
        raise ISOException(sw)
    return resp[0]


def closeLogCh(c, logCh):
    apdu = [0, INS_MANAGE_LOGCH, 0x80, logCh, 0]
    resp, sw1, sw2 = c.transmit(apdu)
    sw = (sw1 << 8) + sw2
    if sw != 0x9000:
        raise ISOException(sw)


class GetStatusData:
    """Represent and interpret data from Get status for Packages and Modules"""
    def __init__(self, respdataPM, respdataApp):
        ind = 0
        self.packages = []
        while len(respdataPM) > ind:
            length = respdataPM[ind]
            pack_aid = l2s(respdataPM[ind+1: ind+1+length])
            ind += length + 1
            lcs = respdataPM[ind]
            priv = respdataPM[ind+1]
            nmod = respdataPM[ind+2]
            ind += 3
            mods = []
            for i in xrange(nmod):
                length = respdataPM[ind]
                mods.append(l2s(respdataPM[ind+1: ind+1+length]))
                ind += length + 1
            self.packages.append({'pack_aid': pack_aid,
                                  'lcs': lcs,
                                  'priv': priv,
                                  'modules': mods})
        ind = 0
        self.insts = []
        while len(respdataApp) > ind:
            length = respdataApp[ind]
            app_aid = l2s(respdataApp[ind+1: ind+1+length])
            ind += length + 1
            lcs = respdataApp[ind]
            priv = respdataApp[ind+1]
            ind += 2
            self.insts.append({'app_aid': app_aid,
                               'lcs': lcs,
                               'priv': priv})

    def __str__(self):
        res = ''
        for p in self.packages:
            res += "Package AID: %s %02X %02X\n" % \
                   (hexlify(p['pack_aid']).upper().ljust(32),
                    p['lcs'], p['priv'])
            for m in p['modules']:
                res += "      module %s\n" % hexlify(m).upper().ljust(32)
        for p in self.insts:
            res += "Insts AID  : %s %02X %02X\n" % \
                   (hexlify(p['app_aid']).upper().ljust(32),
                    p['lcs'], p['priv'])
        return res


def getStatus(sc, AID_pref=''):
    """ Issue GET STATUS apdu for packages and modules, and instances. """
    res = {}
    for P1 in (0x10, 0x40):
        apdu = [0x80, INS_GETSTATUS, P1, 0, 2+len(AID_pref), 0x4F,
                len(AID_pref)] + s2l(AID_pref)
        respdata, sw1, sw2 = sc.transmit(apdu)
        sw = (sw1 << 8) + sw2
        while sw == 0x6310:
            apdu = [0x80, INS_GETSTATUS, P1, 1, 2+len(AID_pref), 0x4F,
                    len(AID_pref)] + s2l(AID_pref)
            resp, sw1, sw2 = sc.transmit(apdu)
            respdata += resp
            sw = (sw1 << 8) + sw2
        if sw != 0x9000:
            raise ISOException(sw)
        res[P1] = respdata
    return GetStatusData(res[0x10], res[0x40])


def getData(c, tag):
    P1 = tag >> 8
    P2 = tag & 0xFF
    apdu = [0x80, INS_GETDATA, P1, P2, 0]
    resp, sw1, sw2 = c.transmit(apdu)
    if sw1 == 0x6C:
        apdu[4] = sw2
        resp, sw1, sw2 = c.transmit(apdu)
    sw = (sw1 << 8) + sw2
    if sw != 0x9000:
        raise ISOException(sw)
    return l2s(resp)


def getExtCardRes(c):
    """ Issue GET DATA with tag FF21 in order to receive Extended
Card Resources (GP 2.2.1, 11.3 & ETSI TS 102.226, 8.2.1.7).
Returns [num. of install applets, free NVM, free RAM]"""
    # CLA = 0x00: return only value
    # CLA = 0x80: return TLV, i.e. 0xFF21 #(value)
    apdu = [0x80, INS_GETDATA, 0xFF, 0x21, 0]
    resp, sw1, sw2 = c.transmit(apdu)
    if sw1 == 0x6C:
        apdu[4] = sw2
        resp, sw1, sw2 = c.transmit(apdu)
    sw = (sw1 << 8) + sw2
    if sw != 0x9000:
        raise ISOException(sw)
    payload = l2s(resp)
    result = [s2int(findTLValue(payload, (0xFF21, tag))) for
              tag in (0x81, 0x82, 0x83)]
    return result


def selectFile(c, path, logCh=0):
    """ Select file by path from MF or MF for empty path """
    if len(path) > 0:
        apdu = [logCh, INS_SELECT, 8, 4, len(path)] + s2l(path)
    else:
        apdu = [logCh, INS_SELECT, 0, 4, 2, 0x3F, 0x00]
    resp, sw1, sw2 = c.transmit(apdu)
    if sw1 == 0x61:
        resp, sw1, sw2 = c.transmit([0, 0xC0, 0, 0, sw2])
    sw = (sw1 << 8) + sw2
    if sw != 0x9000:
        raise ISOException(sw)
    return l2s(resp)


def readBinary(c, le, logCh=0, offset=0):
    """Read Binary on currently selected EF"""
    P1 = (offset >> 8) & 0x7F
    P2 = offset & 0xFF
    apdu = [logCh, INS_READBIN, P1, P2, le]
    resp, sw1, sw2 = c.transmit(apdu)
    sw = (sw1 << 8) + sw2
    if sw != 0x9000:
        raise ISOException(sw)
    return l2s(resp)


def readRecord(c, recNum, logCh=0):
    """ Read record from currently selected EF"""
    apdu = [logCh, INS_READREC, recNum, 4, 0]
    resp, sw1, sw2 = c.transmit(apdu)
    if sw1 == 0x6C:
        apdu[4] = sw2
        resp, sw1, sw2 = c.transmit(apdu)
    sw = (sw1 << 8) + sw2
    if sw != 0x9000:
        raise ISOException(sw)
    return l2s(resp)

def updateBinary(c, data, logCh=0, offset=0):
    """Update binary on currently selected EF"""
    assert len(data) < 0x100
    P1 = (offset >> 8) & 0x7F
    P2 = offset & 0xFF
    apdu = [logCh, INS_UPDBIN, P1, P2, len(data)] + s2l(data)
    resp, sw1, sw2 = c.transmit(apdu)
    sw = (sw1 << 8) + sw2
    if sw != 0x9000:
        raise ISOException(sw)


def updateRecord(c, recNum, data, logCh=0):
    """ Update record from currently selected EF"""
    assert len(data) < 0x100
    apdu = [logCh, INS_UPDREC, recNum, 4, len(data)] + s2l(data)
    resp, sw1, sw2 = c.transmit(apdu)
    sw = (sw1 << 8) + sw2
    if sw != 0x9000:
        raise ISOException(sw)

def verifyPin(c, pin=None, P2=0x01, logCh=0):
    """Verify PIN
pin   - value (str, 4-8bytes). If None, just get number of tries.
P2    - PIN identification (0x01: PIN1 (default), 0x81: PIN2, etc.)
logCh - logical channel (default 0)
Return number of remaing tries or True if verification succesfull.
"""
    lc = 0 if pin is None else 8
    apdu = [logCh, INS_VERIFY_PIN, 0, P2, lc]
    if pin is not None:
        assert 4 <= len(pin) <= 8
        pin += '\xFF' * (8 - len(pin))
        apdu += s2l(pin)
    resp, sw1, sw2 = c.transmit(apdu)
    sw = (sw1 << 8) + sw2
    if sw == 0x6983:  # PIN blocked
        return 0
    if 0x63C0 <= sw <= 0x63CA:  # remaining tries
        return sw - 0x63C0
    if sw != 0x9000:
        raise ISOException(sw)
    return True   # pin verified

def changePin(c, oldPin, newPin, P2=0x01, logCh=0):
    """Change PIN
oldPin   - old PIN value (str, 4-8bytes)
newPin   - new PIN value (str, 4-8bytes)
P2    - PIN identification (0x01: PIN1 (default), 0x81: PIN2, etc.)
logCh - logical channel (default 0)
"""
    assert 4 <= len(oldPin) <= 8
    oldPin += '\xFF' * (8 - len(oldPin))
    assert 4 <= len(newPin) <= 8
    newPin += '\xFF' * (8 - len(newPin))
    apdu = [logCh, INS_CHANGE_PIN, 0, P2, 0x10] + s2l(oldPin) + s2l(newPin)
    resp, sw1, sw2 = c.transmit(apdu)
    sw = (sw1 << 8) + sw2
    if sw != 0x9000:
        raise ISOException(sw)

def disablePin(c, pin, P2=0x01, logCh=0):
    """Disable PIN
pin   - PIN value (str, 4-8bytes)
P2    - PIN identification (0x01: PIN1 (default), 0x81: PIN2, etc.)
logCh - logical channel (default 0)
"""
    assert 4 <= len(pin) <= 8
    pin += '\xFF' * (8 - len(pin))
    apdu = [logCh, INS_DISABLE_PIN, 0, P2, 8] + s2l(pin)
    resp, sw1, sw2 = c.transmit(apdu)
    sw = (sw1 << 8) + sw2
    if sw != 0x9000:
        raise ISOException(sw)
    
def enablePin(c, pin, P2=0x01, logCh=0):
    """Enable PIN
pin   - PIN value (str, 4-8bytes)
P2    - PIN identification (0x01: PIN1 (default), 0x81: PIN2, etc.)
logCh - logical channel (default 0)
"""
    assert 4 <= len(pin) <= 8
    pin += '\xFF' * (8 - len(pin))
    apdu = [logCh, INS_ENABLE_PIN, 0, P2, 8] + s2l(pin)
    resp, sw1, sw2 = c.transmit(apdu)
    sw = (sw1 << 8) + sw2
    if sw != 0x9000:
        raise ISOException(sw)
    
def unblockPin(c, puk, newPin, P2=0x01, logCh=0):
    """unblock PIN
puk    - new PIN value (str, 4-8bytes)
newPin - PIN value (str, 4-8bytes)
P2     - PIN identification (0x01: PIN1 (default), 0x81: PIN2, etc.)
logCh  - logical channel (default 0)
"""
    assert len(puk) == 8
    assert 4 <= len(newPin) <= 8
    newPin += '\xFF' * (8 - len(newPin))
    apdu = [logCh, INS_UNBLOCK_PIN, 0, P2, 0x10] + s2l(puk) + s2l(newPin)
    resp, sw1, sw2 = c.transmit(apdu)
    sw = (sw1 << 8) + sw2
    if sw != 0x9000:
        raise ISOException(sw)

def selectUSIM(c, logCh=0):
    """Select USIM, return AID
Read EF_DIR, USIM = first application with AID of USIM (3GPP TS 31.110)"""
    # read EF_DIR
    infoDIR = selectFile(c, unhexlify('2F00'), logCh)
    # see ETSI 102.221 11.1.1.4.3 for coding
    fileDesc = findTLValue(infoDIR, (0x62, 0x82))
    assert len(fileDesc) == 5 and \
        fileDesc[:2] == '\x42\x21'  # linear EF
    recLen, nRec = unpack(">HB", fileDesc[2:5])
    aids = []
    for recNum in xrange(1, nRec+1):
        try:
            r = readRecord(c, recNum)
            if r == '\xFF' * len(r):
                continue
            aid = findTLValue(r, (0x61, 0x4F))
            aids.append(aid)
        except ISOException:
            break
    # search for USIM
    for aid in aids:
        if aid[:7] == unhexlify('A0000000871002'):
            infoUSIM = selectApplet(c, aid, logCh)
            return aid
    return None

def cardInfo(c, USIMpin=None, logCh=0):
    """Deselect, read EF_DIR, EF_ICCID"""
    resetCard(c)
    histBytes = l2s(ATR(c.getATR()).getHistoricalBytes())
    infoMF = selectFile(c, '', logCh)
    # read EF_ICCID
    infoICCID = selectFile(c, unhexlify('2FE2'), logCh)
    fileSize = s2int(findTLValue(infoICCID, (0x62, 0x80)))
    assert fileSize == 10, "Wrong size of EF_ICCID"
    iccid = swapNibbles(readBinary(c, fileSize))
    # read EF_DIR
    infoDIR = selectFile(c, unhexlify('2F00'), logCh)
    # see ETSI 102.221 11.1.1.4.3 for coding
    fileDesc = findTLValue(infoDIR, (0x62, 0x82))
    assert len(fileDesc) == 5 and \
        fileDesc[:2] == '\x42\x21'  # linear EF
    recLen, nRec = unpack(">HB", fileDesc[2:5])
    dirDO = []
    for recNum in xrange(1, nRec+1):
        try:
            r = readRecord(c, recNum)
            if r == '\xFF' * len(r):
                continue
            aid = findTLValue(r, (0x61, 0x4F))
            label = findTLValue(r, (0x61, 0x50))
            dirDO.append({'AID': aid, 'label': label})
        except ISOException:
            break
    # select USIM and try to read IMSI
    aids = [DO['AID'] for DO in dirDO
            if DO['AID'][:7] == unhexlify('A0000000871002')]
    if len(aids) >= 1:
        aid_usim = aids[0]  # choose the first AID found
    else:
        aid_usim = None
    if aid_usim:
        infoUSIM = selectApplet(c, aid_usim, logCh)
        if USIMpin is not None:
            verifyPin(c, USIMpin, logCh=logCh)
        infoIMSI = selectFile(c, unhexlify('7FFF6F07'), logCh)
        try:
            bimsi = readBinary(c, 9, logCh)
            digits = reduce(lambda d, n: d + [ord(n) & 0x0F, ord(n) >> 4],
                            bimsi[1:1+ord(bimsi[0])], [])
            digits.pop(0)          # remove first nibble 8 or 9
            while digits[-1] == 0x0F:
                digits.pop()  # remove trailing F
            imsi = ''.join([chr(ord('0')+i) for i in digits])
        except ISOException:
            imsi = None
    else:
        imsi = None
    # select default applet and get tags 45 and 42
    selectApplet(c, '', logCh)
    try:
        iin = findTLValue(getData(c, T_IIN), (T_IIN,))
    except ISOException:
        iin = None
    try:
        cin = findTLValue(getData(c, T_CIN), (T_CIN,))
    except ISOException:
        cin = None
    return histBytes, iccid, dirDO, imsi, iin, cin
