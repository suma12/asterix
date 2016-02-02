# -*- coding: utf-8 -*-
""" asterix/__init__.py

__author__ = "Petr Tobiska"

Author: Petr Tobiska, mailto:petr.tobiska@gmail.com, petr.tobiska@gemalto.com
Date: 2015-11-14

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
"""

from . import mycard, formutil, GAF, APDU, applet, SCP02, SCP03
from . import SecurePacket, CAT
__all__ = ( mycard, formutil, GAF, APDU, applet, SCP02, SCP03,
            SecurePacket, CAT )
