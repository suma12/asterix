""" asterix/CAT.py

__author__ = "Petr Tobiska"

Author: Petr Tobiska, mailto:petr.tobiska@gmail.com, petr.tobiska@gemalto.com
Date: 2015-11-16

This file is part of asterix, a framework for  communication with smartcards
 based on pyscard. This file implementes Card Application Toolkit operations.

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

from struct import pack, unpack
from binascii import hexlify
# asterix
from formutil import int2s, l2s, derLen, derLV, split2TLV
__all__ = ('ProactiveException', 'SMS_MO', 'SMS_MT', 'ProactiveSession')


class ProactiveException(Exception):
    pass


class TLV(object):
    """ Represesentation of Tag-Length-Value structure.
tag    - u8, u16, u24 integer
value  - string """
    # COMPACT = ISO 7816-4 SIMPLE
    (BER, COMPACT, COMPREH) = range(3)

    def __init__(self, tag, value, typ=BER):
        self.tag = tag
        self.typ = typ
        self.value = value

    def len(self):
        return len(self.value)

    def bytestr(self):
        """ Get byte string representation of TLV, depending on type. """
        # BER, COMPREH: length as in ISO 8825-1 aka X.690
        # COMPACT: length 00-FE or FF xx yy
        tags = int2s(self.tag)
        l = len(self.value)
        if self.typ == TLV.COMPACT:
            if l < 0xFF:
                lens = chr(l)
            else:
                lens = '\xFF' + pack(">H", l)
        else:
            lens = derLen(l)
        return tags + lens + self.value


class ProactiveCommand(object):
    """ Representation of Proactive command. """
    def __init__(self, cmd, qualif, device):
        self.cmd = cmd
        self.qualif = qualif
        self.device = device
        self.TLVs = []


class TerminalResponse(object):
    """ Representation of Terminal response. """
    def __init__(self, proCmd, hook=None, par=None):
        self.cmd = proCmd.cmd
        self.qualif = proCmd.qualif
        self.device = proCmd.device
        self.result = 0     # default value: OK
        self.TLVs = []
        # TBD: add command specific TLVs
        if hook:
            hook(proCmd, self, par)

    def bytestr(self):
        s = ''
        # Command details, Devices, Result TLVs
        for tv in ((T_CMD_DETAILS, pack("BBB", 1, self.cmd, self.qualif)),
                   (T_DEVICES, pack("BB", self.device, DEV_UICC)),
                   (T_RESULT, chr(self.result))):
            s += TLV(*tv).bytestr()
        # other
        for t in self.TLVs:
            s += t.bytestr()
        return s


class SMS_MT(object):
    """ Representation of MT SMS. """
    def __init__(self, **kw):
        # parse kw, put default values if not present
        # SCA is value only, without length, remove num. of digits
        self.SCA = addr2bytestr(*kw.get('SCA', (0x89, 1234567)))[1:]
        self.OA = addr2bytestr(*kw.get('OA', (0x89, 987654321)))
        self.MTI = 0x40  # SMS deliver + UDHI
        self.PID = 0x7F
        self.DCS = 0xF6
        self.SCTS = '\0'*7
        self.UDH = pack("BB", IEI_COMPACK, 0)  # USIM message
        self.concRef = 0
        self.zConc8b = True
        self.messages = {}
        for k in ('MTI', 'PID', 'DCS', 'SCTS', 'UDH', 'concRef'):
            if k in kw:
                self.__dict__[k] = kw[k]
        # checks
        chr(self.MTI)
        chr(self.PID)
        chr(self.DCS)
        assert len(self.SCTS) == 7,\
            "TP-SCTS incorrect '%s'" % hexlify(self.SCTS)

    def createMessages(self, payload, zIncConcRef=True):
        """ Create a list of TPDUs. """
        lenPL = len(payload)
        if self.UDH:
            lenPL += len(self.UDH)
            sizeUD = 139   # 1B for length of UDH
        else:
            sizeUD = 140
        if lenPL <= sizeUD:
            nMes = 1
        else:
            sizeUD = self.zConc8b and 134 or 133
            nMes = 1 + (lenPL - 1)/sizeUD
        if nMes > 1 or self.UDH:
            self.MTI |= 0x40    # make sure UDHI bit set
        else:
            self.MTI &= ~0x40    # clear UDHI bit
        TPheader = chr(self.MTI) + self.OA + chr(self.PID) + \
            chr(self.DCS) + self.SCTS
        if nMes == 1:
            if self.UDH:
                udl = 1 + lenPL
                mes = TPheader + chr(udl) + chr(len(self.UDH)) + \
                    self.UDH + payload
            else:
                mes = TPheader + chr(lenPL) + payload
            return [mes]

        # concat header without seq. number: 8b/16b reference
        concatHead = self.zConc8b and \
            pack("BBB", 0, 3, self.concRef % 0x100) or \
            pack(">BBH", 8, 4, self.concRef % 0x10000)
        concatHead += chr(nMes)
        if zIncConcRef:
            self.concRef += 1
        # build the first message
        udl = 140
        udh = concatHead + chr(1)
        if self.UDH:
            udh += self.UDH
        udh = chr(len(udh)) + udh
        plOff = 0
        plLen = 140 - len(udh)
        mes = TPheader + chr(udl) + udh + payload[plOff:plOff+plLen]
        messages = [mes]
        # build next messages
        concatHead = chr(len(concatHead) + 1) + concatHead
        plOff += plLen
        plLen = 140 - len(concatHead) - 1
        for i in xrange(2, nMes):
            mes = TPheader + chr(udl) + concatHead + chr(i) + \
                  payload[plOff:plOff+plLen]
            plOff += plLen
            messages.append(mes)
        # the last message
        concatHead += chr(nMes)
        plLen = len(payload) - plOff + len(concatHead)
        mes = TPheader + chr(plLen) + concatHead + payload[plOff:]
        messages.append(mes)
        return messages

    def parseTPDU(self, tpdu):
        """ Parse TPDU from Envelope SMS-PP download 'D1', accumulate """
        MTI = ord(tpdu[0])
        ndig = ord(tpdu[1])
        off = (ndig+7)/2
        OA = tpdu[1:off]
        PID, DCS = [ord(x) for x in tpdu[off:off+2]]
        SCTS = tpdu[off+2:off+9]
        assert len(tpdu) == off + 10 + ord(tpdu[off+9]), \
            "Wrong UDL %d" % ord(tpdu[off+9])
        off += 10
        if MTI & 0x40:     # UDH present
            noff = off+1 + ord(tpdu[off])
            UDH = tpdu[off+1:noff]
            off = noff
            # split UDH to IE
            IE = []
            o = 0
            while o < len(UDH):
                try:
                    l = ord(UDH[1])
                    IE.append(UDH[o:o+l+2])
                    o += l+2
                except Exception:
                    raise AssertionError("Mismatched UDH " +
                                         hexlify(UDH).upper())
            # find concat IE
            concatUDH = [u for u in IE
                         if ord(u[0]) in (IEI_CONCAT8b, IEI_CONCAT16b)]
            otherUDH = [u for u in IE
                        if ord(u[0]) not in (IEI_CONCAT8b, IEI_CONCAT16b)]
            assert len(concatUDH) <= 1, "More than 1 concat IE"
            if len(concatUDH) == 0:
                self.UDH = UDH
                self.nMes = 1
                self.messages[1] = tpdu[off:]
                return
            UDH = derLV(''.join(otherUDH))
            concatIE = concatUDH[0]
            assert ord(concatIE[0]) in (IEI_CONCAT8b, IEI_CONCAT16b)
            zConc8b = ord(concatIE[0]) == IEI_CONCAT8b
            if zConc8b:
                assert len(concatIE) == 5, "Wrong Concat 8b IE"
                concRef, nMes, iMes = unpack("BBB", concatIE[2:])
            else:
                assert len(concatIE) == 6, "Wrong Concat 16b IE"
                concRef, nMes, iMes = unpack(">HBB", concatIE[2:])
            if self.messages:
                for i in ('MTI', 'OA', 'PID', 'DCS', 'SCTS', 'zConc8b',
                          'concRef', 'nMes'):
                    if self.__dict__[i] != locals()[i]:
                        print "Parameter %s changed: '%s' -> '%s'" % \
                            (i, self.__dict__[i].__str__(),
                              locals()[i].__str__())
                if iMes in self.messages:
                    print "Duplicate message %d, ignored" % iMes
            else:  # the first (or the only) message
                self.MTI, self.OA, self.PID, self.DCS, self.SCTS = \
                    MTI, OA, PID, DCS, SCTS
                self.zConc8b, self.concRef, self.nMes = zConc8b, concRef, nMes
            if iMes == 1:
                self.UDH = UDH
            self.messages[iMes] = tpdu[off:]
        else:  # UDH not present
            self.UDH = ''
            self.nMes = 1
            self.messages[1] = tpdu[off:]

    def mergeUserData(self):
        """ Merges sec. data from received TPDUs.
Return (UDH, payload)"""
        diffset = set(xrange(1, self.nMes+1)) - set(self.messages.keys())
        assert diffset == set(), "Missing messages: " + list(diffset).__str__()
        payload = ''.join([self.messages[i] for i in xrange(1, self.nMes+1)])
        return(self.UDH, payload)

    def createEnv(self, messages, cla=0x80):
        """ Create APDU with Envelope Send SM from list of messages. """
        commonTLVs = TLV(T_DEVICES, pack("BB", DEV_NETWORK, DEV_UICC))\
            .bytestr()
        commonTLVs += TLV(T_ADDRESS, self.SCA).bytestr()
        apdus = []
        for mes in messages:
            data = commonTLVs + TLV(T_SMS_TPDU, mes).bytestr()
            data = TLV(T_ENVSMS, data).bytestr()
            apdu = [cla, INS_ENV, 0, 0, len(data)] + \
                   [ord(x) for x in data]
            apdus.append(apdu)
        return apdus


class SMS_MO(object):
    """ Represents SMS_MO object."""
    def __init__(self):
        self.messages = {}
        self.nMes = None
        self.SCA = None
        self.MTI = None
        self.DA = None
        self.PID = None
        self.DCS = None
        self.VP = None
        self.UDH = None
        self.concRef = None
        self.zConc8b = None
        self.payload = None

    def addMessage(self, tSCA, TPDU):
        """ Add a short message to the object, SCA and TPDU are TLV."""
        if tSCA:
            SCA = tSCA.value
        MTI = ord(TPDU.value[0])
        ndig = ord(TPDU.value[2])
        off = 4 + (ndig + 1)/2
        DA = TPDU.value[2:off]
        PID = ord(TPDU.value[off])
        DCS = ord(TPDU.value[off+1])
        off += 2
        if(MTI & 0x18 == 0x10):
            VP = TPDU.value[off]
            off += 1
        elif(MTI & 0x18 != 0):
            VP = TPDU.value[off:off+7]
            off += 7
        else:
            VP = None
        udl = ord(TPDU.value[off])
        assert udl + off + 1 == len(TPDU.value),\
            "Wrong UDL %02X vs. %d" % (udl, len(TPDU.value) - off - 1)
        UD = TPDU.value[off+1:]
        if self.nMes is None:   # the first (or the only) message
            self.SCA, self.MTI, self.DA, self.PID, self.DCS, self.VP = \
                SCA, MTI, DA, PID, DCS, VP
        else:
            for i in ('SCA', 'MTI', 'DA', 'PID', 'DCS', 'VP'):
                if self.__dict__[i] != locals()[i]:
                    print "Parameter %s changed: '%s' -> '%s'" % \
                        (i, self.__dict__[i].__str__(), locals()[i].__str__())
        # analyze concatenation
        if MTI & 0x40:
            UDHL = ord(UD[0])
            IEstring = UD[1:1+UDHL]
            IEs = []
            off = 0
            while off < UDHL:
                tag, l = unpack("BB", IEstring[off:off+2])
                off += 2
                assert off + l <= UDHL,\
                    "Wrong IEI: %s" % hexlify(IEstring).upper()
                IEs.append(TLV(tag, IEstring[off:off+l]))
                off += l
            # find concat IE
            concIE = [x for x in IEs if x.tag in (IEI_CONCAT8b, IEI_CONCAT16b)]
            assert len(concIE) <= 1, "More concat IEs"
            if concIE:
                self.zConc8b = concIE[0].tag == IEI_CONCAT8b
                assert concIE[0].len() == (self.zConc8b and 3 or 4),\
                    "Wrong length of concat IE"
                concRef = unpack(self.zConc8b and "B" or ">H",
                                 concIE[0].value[:-2])[0]
                nMes, iMes = [ord(x) for x in concIE[0].value[-2:]]
                if self.nMes is None:
                    self.nMes, self.concRef = nMes, concRef
                else:
                    assert self.concRef is not None, "Concat ref not defined"
                    assert (self.nMes, self.concRef) == (nMes, concRef),\
                        ("Different concat ref %X vs %X " +
                         "or number of messages %d vs %d") %\
                        (self.concRef, concRef, self.nMes, nMes)
                if iMes in self.messages:
                    print "Duplicate message %d, ignored" % iMes
                    return
                self.messages[iMes] = UD[1+UDHL:]
            else:
                iMes = self.nMes = 1
            self.messages[iMes] = UD[1+UDHL:]
            otherIE = [x for x in IEs
                       if x.tag not in (IEI_CONCAT8b, IEI_CONCAT16b)]
            if otherIE:
                if iMes == 1:
                    UDH = ''.join([x.bytestr() for x in otherIE])
                    self.UDH = chr(len(UDH)) + UDH
                else:
                    raise ValueError("IE in non-first message")
        else:  # no UDH
            self.UDH = ''
            iMes = self.nMes = 1
            self.messages[1] = UD
        return iMes, self.nMes

    def mergeMessages(self):
        """ Merge accumulated messages. """
        if self.nMes is None:
            return (self.UDH, '')

        # check that all messages are stored
        missing = [i for i in range(1, self.nMes+1) if i not in self.messages]
        if missing:
            raise ValueError("Missing messages: %s" % ', '.join(
                ['%d' % i for i in missing]))
        self.payload = ''.join([self.messages[i]
                                for i in xrange(1, self.nMes+1)])
        return (self.UDH, self.payload)

    def __str__(self):
        if self.nMes:
            mesList = ' '.join(["%d" % i for i in range(1, self.nMes+1)
                                if i in self.messages])
            return "SMS MO, nMes=%d [%s]" % (self.nMes, mesList)
        else:
            return "SMS MO, uninitialized"


def addr2bytestr(TON_NPI, number):
    """ Transform TON_NPI + number to bytestr representation:
<num of digits><TON_NPI byte><swapped digits padded by F>."""
    digits = []
    while number > 0:
        digits.insert(0, number % 10)
        number /= 10
    ndig = len(digits)
    assert ndig <= 20, "Address - number longer than 20 digits"
    if ndig % 2:
        digits.append(0x0F)  # if odd number of digits pad by F
    l = [chr((x << 4) + y) for (x, y) in zip(digits[1::2], digits[0::2])]
    return chr(ndig) + chr(TON_NPI) + ''.join(l)


class ProactiveSession(object):
    """ Class for Proactive Session - Terminal Profile, Proactive commands ."""
    def __init__(self, connection, logCh=0):
        self.connection = connection
        self.logCh = logCh
        self.hooks = {PAC_POLL_INTERVAL: hook_poll_interval,
                      PAC_GET_INPUT: hook_get_input,
                      PAC_SEND_SM: hook_send_sm,
                      PAC_DISP_TEXT: hook_display_text}

    def CLA(self):
        if self.logCh < 4:
            return 0x80 + self.logCh
        else:
            return 0xC0 + (self.logCh - 4)

    def terminalProfile(self, capabilities='\xFF'*10, par=None):
        apdu = [self.CLA(), INS_TP, 0, 0, len(capabilities)] + \
               [ord(x) for x in capabilities]
        resp, sw1, sw2 = self.connection.transmit(apdu)
        while sw1 == 0x91:
            sw1, sw2 = self.fetchProcess(sw2, par)
        sw = (sw1 << 8) + sw2
        if sw != 0x9000:
            raise ProactiveException("Terminal profile")

    def fetchProcess(self, sw2, par=None):
        apdu = [self.CLA(), INS_FETCH, 0, 0, sw2]
        resp, sw1, sw2 = self.connection.transmit(apdu)
        sw = (sw1 << 8) + sw2
        if sw != 0x9000:
            raise ProactiveException("Fetch")
        proCmd = self.parseProactiveCmd(resp)
        hook = self.hooks.get(proCmd.cmd, None)
        termResp = TerminalResponse(proCmd, hook, par)
        termResps = termResp.bytestr()
        apdu = [self.CLA(), INS_TR, 0, 0, len(termResps)] + \
               [ord(x) for x in termResps]
        resp, sw1, sw2 = self.connection.transmit(apdu)
        return sw1, sw2

    def parseProactiveCmd(self, resp):
        """ Parse Proactive command from fetched byte array. """
        try:
            res = split2TLV(l2s(resp))
            assert len(res) == 1
            assert res[0][0] == T_PROCMD
        except AssertionError:
            raise ProactiveException("Wrong ProCmd tag / length")
        try:
            tlvs = split2TLV(res[0][1])
        except AssertionError:
            raise ProactiveException("Wrong TLVs in proactive command")
        # parse Command details and Devices TLVs
        tlv = tlvs.pop(0)
        if 0x7F & tlv[0] != T_CMD_DETAILS or len(tlv[1]) != 3 \
           or tlv[1][0] != '\x01':
            raise ProactiveException("ProCmd wrong Command details")
        cmd, qualif = unpack("BB", tlv[1][1:])
        # parse Command details and Devices TLVs
        tlv = tlvs.pop(0)
        if 0x7F & tlv[0] != T_DEVICES or len(tlv[1]) != 2 \
           or tlv[1][0] != chr(DEV_UICC):
            raise ProactiveException("ProCmd wrong Devices")
        dev = ord(tlv[1][1])
        proCmd = ProactiveCommand(cmd, qualif, dev)
        # parse rest of TLVs
        for tlv in tlvs:
            proCmd.TLVs.append(TLV(*tlv))
        return proCmd

#  ###### default hook functions ##############


def hook_poll_interval(proCmd, termResp, par):
    """ Terminal response hook for Poll Interval PaC. """
    tlvs = [x for x in proCmd.TLVs if 0x7F & x.tag == T_DURATION]
    if not tlvs:
        raise ProactiveException("Duration missing in Poll interval")
    termResp.TLVs.extend(tlvs)


def hook_get_input(proCmd, termResp, par):
    """ Terminal response hook for Get Input PaC.
Expects par contains dictionary with 'GetInputResp': <response text>.
Repeat/cut the provided text if necessary."""
    tlv_ts = [x for x in proCmd.TLVs if 0x7F & x.tag == T_TEXT_STR]
    tlv_rl = [x for x in proCmd.TLVs if 0x7F & x.tag == T_RESP_LEN]
    assert len(tlv_ts) == 1, "Text string non-unique in Get Input"
    assert len(tlv_rl) == 1 and len(tlv_rl[0].len()) == 2, \
        "Missing or incorrect Response length in Get Input"
    DCS = tlv_ts[0].value[0]
    prompt = tlv_ts[0].value[1:]
    lenmin, lenmax = [ord(x) for x in tlv_rl[0].value[0]]
    assert lenmin <= lenmax, "Min length > max length in Get Input"
    print "PaC Get Input DCS=%02X '%s', resp. len=<%d:%d>" % (
        ord(DCS), prompt, lenmin, lenmax)
    if par is None or 'GetInputResp' not in par:
        resptext = 'Default Text '
    else:  # rotate provided values
        if isinstance(par['GetInputResp'], list):
            resptext = par['GetInputResp'].pop(0)
            par['GetInputResp'] += resptext
        else:
            resptext = par['GetInputResp']
    if len(resptext) < lenmin:
        resptext = resptext*(lenmin/len(resptext) + 1)[:lenmin]
    elif len(resptext) > lenmax:
        resptext = resptext[:lenmax]
    print "T-R with text '%s'" % resptext
    termResp.TLVs.append(TLV(T_TEXT_STR, DCS+resptext))


def hook_send_sm(proCmd, termResp, par):
    """ Cummulate Short messages into SMS_MO object and generate TR.
Expects that par contains dictionary with 'SMS_MO': <SMS_MO object>."""
    tlv_sca = [x for x in proCmd.TLVs if 0x7F & x.tag == T_ADDRESS]
    tlv_tpdu = [x for x in proCmd.TLVs if 0x7F & x.tag == T_SMS_TPDU]
    assert len(tlv_sca) <= 1, "More than one Address TLV in Send SMS"
    assert len(tlv_tpdu) == 1, "Missing or non-unique TPDU TLV in Send SMS"
    sca = len(tlv_sca) == 1 and tlv_sca[0] or None
    tpdu = tlv_tpdu[0]
    if par is not None and 'SMS_MO' in par:
        iMes, nMes = par['SMS_MO'].addMessage(sca, tpdu)
        print "PaC Send SMS, message %d of %d" % (iMes, nMes)


def hook_display_text(proCmd, termResp, par):
    """ Terminal response for Display text. """
    tlv_dt = [x for x in proCmd.TLVs if 0x7F & x.tag == T_TEXT_STR]
    assert len(tlv_dt) == 1, \
        "Missing or non-unique Text String TLV in Display Text"
    dt = tlv_dt[0].value
    tlv_dur = [x for x in proCmd.TLVs if 0x7F & x.tag == T_DURATION]
    assert len(tlv_dur) <= 1, "More than one Duration TLV in Display Text"
    if len(tlv_dur) > 0:
        dur = tlv_dur[0].value
        assert len(dur) == 2 and ord(dur[0]) <= 2 and dur[1] != '\0',\
            "Wrong format of Duration value"
        if dur[0] == '\x00':
            duration = "%dmin" % ord(dur[1])
        elif dur[0] == '\x01':
            duration = "%ds" % ord(dur[1])
        else:
            duration = "%.1fs" % (ord(dur[1]) / 10.)
        duration = "; duration = "+duration
    else:
        duration = ""
    print "PaC Display Text, DCS=%02X '%s'%s" % (
        ord(dt[0]), dt[1:], duration)

# ## constants ###
# tags for proactive commands and envelopes
T_PROCMD = 0xD0
T_ENVSMS = 0xD1
# tags for comprehension TLVs
T_CMD_DETAILS = 0x01
T_DEVICES     = 0x02
T_RESULT      = 0x03
T_DURATION    = 0x04
T_ADDRESS     = 0x06
T_SMS_TPDU    = 0x0B
T_TEXT_STR    = 0x0D
T_RESP_LEN    = 0x11
T_EVT_LIST    = 0x19
# command types
PAC_POLL_INTERVAL = 0x03
PAC_SETUP_EV_LIST = 0x05
PAC_SEND_SM       = 0x13
PAC_DISP_TEXT     = 0x21
PAC_GET_INPUT     = 0x23
# devices
DEV_KEYPAD    = 0x01
DEV_DISPLAY   = 0x02
DEV_UICC      = 0x81
DEV_TERMINAL  = 0x82
DEV_NETWORK   = 0x83
INS_TP    = 0x10
INS_FETCH = 0x12
INS_TR    = 0x14
INS_ENV   = 0xC2
# Events in Event list ETSI 102.223, 8.25
EVT_DATA_AVAIL = 0x09
EVT_CHAN_STAT  = 0x0A
# general results
GR_OK              = 0
GR_ABORT           = 0x10
GR_MOVEBACK        = 0x11
GR_TIMEOUT         = 0x12
GR_TEMPUNAVAIL     = 0x20
# Information Element Identifier, TS 123.040, 9.2.3.24
IEI_CONCAT8b   = 0x00
IEI_CONCAT16b  = 0x08
IEI_COMPACK    = 0x70  # TS 131.115, 4.2
IEI_RESPPACK   = 0x71  # TS 131.115, 4.4
