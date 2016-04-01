from distutils.core import setup

setup(name='asterix',
      version='0.3dev',
      description=
      'Framework for communication with smartcards based on pyscard.',
      author='Petr Tobiska',
      author_email='petr.tobiska@gmail.com',
      url='https://github.com/suma12/asterix',
      packages=['asterix'],
      platforms=['win32', 'linux2'],
      license='GNU LESSER GENERAL PUBLIC LICENSE',
      long_description="""
asterix is a framework for communication with smartcards based on pyscard

It consists of
 mycard        - a module providing handy primitives for card
                 communication (extensions to pyscard)
 formutil      - a module with formatting utilities
 GAF           - a module for representation and evaluation of ASN1
                 structures
 APDU          - a module for creation and transmission of common
                 APDU to a smartcard
 SCP02         - implementation of Secure Channel Protocol 02 as
                 defined in Global platform
 SCP03         - implementation of Secure Channel Protocol 03 as
                 defined in Global platform
 applet        - a module for loading, installation and deletion
                 of JavaCard applets to a smartcard
 CAT           - a module implementing Card Application Toolkit as
                 defined in ETSI TS 102.223
 SecurePacket  - a module implementing Secure Packet for OTA
                 communication with smartcards

All modules are platform independent, working with Python 2.7

All modules rely on pyscard, a package implementing PCSC layer
for communication with smartcards.
""", )
