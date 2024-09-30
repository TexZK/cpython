import _crc
import hashlib
import zlib
from _crc import BYTE_WIDTH
from _crc import MAX_VALUE
from _crc import MAX_WIDTH

import unittest
from dataclasses import dataclass


@dataclass
class Config:
    width: int
    poly: int
    init: int
    refin: bool
    refout: bool
    xorout: int
    check: int
    residue: int


BYTE_COUNT = 1 << BYTE_WIDTH
BYTE_MASK = BYTE_COUNT - 1
MAX_SIZE = (MAX_WIDTH + BYTE_WIDTH - 1) // BYTE_WIDTH

METHODS = ['bitwise', 'bytewise', 'wordwise']

DATA = b'123456789'
DATA2 = b'abcdef'

TEMPLATES = {
    'crc-10-atm'               : ( 10, 0x0000000000000233, 0x0000000000000000, False, False, 0x0000000000000000, 0x0000000000000199, 0x0000000000000000 ),
    'crc-10-cdma2000'          : ( 10, 0x00000000000003D9, 0x00000000000003FF, False, False, 0x0000000000000000, 0x0000000000000233, 0x0000000000000000 ),
    'crc-10-gsm'               : ( 10, 0x0000000000000175, 0x0000000000000000, False, False, 0x00000000000003FF, 0x000000000000012A, 0x00000000000000C6 ),
    'crc-11-flexray'           : ( 11, 0x0000000000000385, 0x000000000000001A, False, False, 0x0000000000000000, 0x00000000000005A3, 0x0000000000000000 ),
    'crc-11-umts'              : ( 11, 0x0000000000000307, 0x0000000000000000, False, False, 0x0000000000000000, 0x0000000000000061, 0x0000000000000000 ),
    'crc-12-cdma2000'          : ( 12, 0x0000000000000F13, 0x0000000000000FFF, False, False, 0x0000000000000000, 0x0000000000000D4D, 0x0000000000000000 ),
    'crc-12-dect'              : ( 12, 0x000000000000080F, 0x0000000000000000, False, False, 0x0000000000000000, 0x0000000000000F5B, 0x0000000000000000 ),
    'crc-12-gsm'               : ( 12, 0x0000000000000D31, 0x0000000000000000, False, False, 0x0000000000000FFF, 0x0000000000000B34, 0x0000000000000178 ),
    'crc-12-umts'              : ( 12, 0x000000000000080F, 0x0000000000000000, False, True,  0x0000000000000000, 0x0000000000000DAF, 0x0000000000000000 ),
    'crc-13-bbc'               : ( 13, 0x0000000000001CF5, 0x0000000000000000, False, False, 0x0000000000000000, 0x00000000000004FA, 0x0000000000000000 ),
    'crc-14-darc'              : ( 14, 0x0000000000000805, 0x0000000000000000, True,  True,  0x0000000000000000, 0x000000000000082D, 0x0000000000000000 ),
    'crc-14-gsm'               : ( 14, 0x000000000000202D, 0x0000000000000000, False, False, 0x0000000000003FFF, 0x00000000000030AE, 0x000000000000031E ),
    'crc-15-can'               : ( 15, 0x0000000000004599, 0x0000000000000000, False, False, 0x0000000000000000, 0x000000000000059E, 0x0000000000000000 ),
    'crc-15-mpt1327'           : ( 15, 0x0000000000006815, 0x0000000000000000, False, False, 0x0000000000000001, 0x0000000000002566, 0x0000000000006815 ),
    'crc-16-arc'               : ( 16, 0x0000000000008005, 0x0000000000000000, True,  True,  0x0000000000000000, 0x000000000000BB3D, 0x0000000000000000 ),
    'crc-16-cdma2000'          : ( 16, 0x000000000000C867, 0x000000000000FFFF, False, False, 0x0000000000000000, 0x0000000000004C06, 0x0000000000000000 ),
    'crc-16-cms'               : ( 16, 0x0000000000008005, 0x000000000000FFFF, False, False, 0x0000000000000000, 0x000000000000AEE7, 0x0000000000000000 ),
    'crc-16-dds-110'           : ( 16, 0x0000000000008005, 0x000000000000800D, False, False, 0x0000000000000000, 0x0000000000009ECF, 0x0000000000000000 ),
    'crc-16-dect-r'            : ( 16, 0x0000000000000589, 0x0000000000000000, False, False, 0x0000000000000001, 0x000000000000007E, 0x0000000000000589 ),
    'crc-16-dect-x'            : ( 16, 0x0000000000000589, 0x0000000000000000, False, False, 0x0000000000000000, 0x000000000000007F, 0x0000000000000000 ),
    'crc-16-dnp'               : ( 16, 0x0000000000003D65, 0x0000000000000000, True,  True,  0x000000000000FFFF, 0x000000000000EA82, 0x00000000000066C5 ),
    'crc-16-en-13757'          : ( 16, 0x0000000000003D65, 0x0000000000000000, False, False, 0x000000000000FFFF, 0x000000000000C2B7, 0x000000000000A366 ),
    'crc-16-genibus'           : ( 16, 0x0000000000001021, 0x000000000000FFFF, False, False, 0x000000000000FFFF, 0x000000000000D64E, 0x0000000000001D0F ),
    'crc-16-gsm'               : ( 16, 0x0000000000001021, 0x0000000000000000, False, False, 0x000000000000FFFF, 0x000000000000CE3C, 0x0000000000001D0F ),
    'crc-16-ibm-3740'          : ( 16, 0x0000000000001021, 0x000000000000FFFF, False, False, 0x0000000000000000, 0x00000000000029B1, 0x0000000000000000 ),
    'crc-16-ibm-sdlc'          : ( 16, 0x0000000000001021, 0x000000000000FFFF, True,  True,  0x000000000000FFFF, 0x000000000000906E, 0x000000000000F0B8 ),
    'crc-16-iso-iec-14443-3-a' : ( 16, 0x0000000000001021, 0x000000000000C6C6, True,  True,  0x0000000000000000, 0x000000000000BF05, 0x0000000000000000 ),
    'crc-16-kermit'            : ( 16, 0x0000000000001021, 0x0000000000000000, True,  True,  0x0000000000000000, 0x0000000000002189, 0x0000000000000000 ),
    'crc-16-lj1200'            : ( 16, 0x0000000000006F63, 0x0000000000000000, False, False, 0x0000000000000000, 0x000000000000BDF4, 0x0000000000000000 ),
    'crc-16-m17'               : ( 16, 0x0000000000005935, 0x000000000000FFFF, False, False, 0x0000000000000000, 0x000000000000772B, 0x0000000000000000 ),
    'crc-16-maxim-dow'         : ( 16, 0x0000000000008005, 0x0000000000000000, True,  True,  0x000000000000FFFF, 0x00000000000044C2, 0x000000000000B001 ),
    'crc-16-mcrf4xx'           : ( 16, 0x0000000000001021, 0x000000000000FFFF, True,  True,  0x0000000000000000, 0x0000000000006F91, 0x0000000000000000 ),
    'crc-16-modbus'            : ( 16, 0x0000000000008005, 0x000000000000FFFF, True,  True,  0x0000000000000000, 0x0000000000004B37, 0x0000000000000000 ),
    'crc-16-nrsc-5'            : ( 16, 0x000000000000080B, 0x000000000000FFFF, True,  True,  0x0000000000000000, 0x000000000000A066, 0x0000000000000000 ),
    'crc-16-opensafety-a'      : ( 16, 0x0000000000005935, 0x0000000000000000, False, False, 0x0000000000000000, 0x0000000000005D38, 0x0000000000000000 ),
    'crc-16-opensafety-b'      : ( 16, 0x000000000000755B, 0x0000000000000000, False, False, 0x0000000000000000, 0x00000000000020FE, 0x0000000000000000 ),
    'crc-16-profibus'          : ( 16, 0x0000000000001DCF, 0x000000000000FFFF, False, False, 0x000000000000FFFF, 0x000000000000A819, 0x000000000000E394 ),
    'crc-16-riello'            : ( 16, 0x0000000000001021, 0x000000000000B2AA, True,  True,  0x0000000000000000, 0x00000000000063D0, 0x0000000000000000 ),
    'crc-16-spi-fujitsu'       : ( 16, 0x0000000000001021, 0x0000000000001D0F, False, False, 0x0000000000000000, 0x000000000000E5CC, 0x0000000000000000 ),
    'crc-16-t10-dif'           : ( 16, 0x0000000000008BB7, 0x0000000000000000, False, False, 0x0000000000000000, 0x000000000000D0DB, 0x0000000000000000 ),
    'crc-16-teledisk'          : ( 16, 0x000000000000A097, 0x0000000000000000, False, False, 0x0000000000000000, 0x0000000000000FB3, 0x0000000000000000 ),
    'crc-16-tms37157'          : ( 16, 0x0000000000001021, 0x00000000000089EC, True,  True,  0x0000000000000000, 0x00000000000026B1, 0x0000000000000000 ),
    'crc-16-umts'              : ( 16, 0x0000000000008005, 0x0000000000000000, False, False, 0x0000000000000000, 0x000000000000FEE8, 0x0000000000000000 ),
    'crc-16-usb'               : ( 16, 0x0000000000008005, 0x000000000000FFFF, True,  True,  0x000000000000FFFF, 0x000000000000B4C8, 0x000000000000B001 ),
    'crc-16-xmodem'            : ( 16, 0x0000000000001021, 0x0000000000000000, False, False, 0x0000000000000000, 0x00000000000031C3, 0x0000000000000000 ),
    'crc-17-can-fd'            : ( 17, 0x000000000001685B, 0x0000000000000000, False, False, 0x0000000000000000, 0x0000000000004F03, 0x0000000000000000 ),
    'crc-21-can-fd'            : ( 21, 0x0000000000102899, 0x0000000000000000, False, False, 0x0000000000000000, 0x00000000000ED841, 0x0000000000000000 ),
    'crc-24-ble'               : ( 24, 0x000000000000065B, 0x0000000000555555, True,  True,  0x0000000000000000, 0x0000000000C25A56, 0x0000000000000000 ),
    'crc-24-flexray-a'         : ( 24, 0x00000000005D6DCB, 0x0000000000FEDCBA, False, False, 0x0000000000000000, 0x00000000007979BD, 0x0000000000000000 ),
    'crc-24-flexray-b'         : ( 24, 0x00000000005D6DCB, 0x0000000000ABCDEF, False, False, 0x0000000000000000, 0x00000000001F23B8, 0x0000000000000000 ),
    'crc-24-interlaken'        : ( 24, 0x0000000000328B63, 0x0000000000FFFFFF, False, False, 0x0000000000FFFFFF, 0x0000000000B4F3E6, 0x0000000000144E63 ),
    'crc-24-lte-a'             : ( 24, 0x0000000000864CFB, 0x0000000000000000, False, False, 0x0000000000000000, 0x0000000000CDE703, 0x0000000000000000 ),
    'crc-24-lte-b'             : ( 24, 0x0000000000800063, 0x0000000000000000, False, False, 0x0000000000000000, 0x000000000023EF52, 0x0000000000000000 ),
    'crc-24-openpgp'           : ( 24, 0x0000000000864CFB, 0x0000000000B704CE, False, False, 0x0000000000000000, 0x000000000021CF02, 0x0000000000000000 ),
    'crc-24-os-9'              : ( 24, 0x0000000000800063, 0x0000000000FFFFFF, False, False, 0x0000000000FFFFFF, 0x0000000000200FA5, 0x0000000000800FE3 ),
    'crc-3-gsm'                : (  3, 0x0000000000000003, 0x0000000000000000, False, False, 0x0000000000000007, 0x0000000000000004, 0x0000000000000002 ),
    'crc-3-rohc'               : (  3, 0x0000000000000003, 0x0000000000000007, True,  True,  0x0000000000000000, 0x0000000000000006, 0x0000000000000000 ),
    'crc-30-cdma'              : ( 30, 0x000000002030B9C7, 0x000000003FFFFFFF, False, False, 0x000000003FFFFFFF, 0x0000000004C34ABF, 0x0000000034EFA55A ),
    'crc-31-philips'           : ( 31, 0x0000000004C11DB7, 0x000000007FFFFFFF, False, False, 0x000000007FFFFFFF, 0x000000000CE9E46C, 0x000000004EAF26F1 ),
    'crc-32-aixm'              : ( 32, 0x00000000814141AB, 0x0000000000000000, False, False, 0x0000000000000000, 0x000000003010BF7F, 0x0000000000000000 ),
    'crc-32-autosar'           : ( 32, 0x00000000F4ACFB13, 0x00000000FFFFFFFF, True,  True,  0x00000000FFFFFFFF, 0x000000001697D06A, 0x00000000904CDDBF ),
    'crc-32-base91-d'          : ( 32, 0x00000000A833982B, 0x00000000FFFFFFFF, True,  True,  0x00000000FFFFFFFF, 0x0000000087315576, 0x0000000045270551 ),
    'crc-32-bzip2'             : ( 32, 0x0000000004C11DB7, 0x00000000FFFFFFFF, False, False, 0x00000000FFFFFFFF, 0x00000000FC891918, 0x00000000C704DD7B ),
    'crc-32-cd-rom-edc'        : ( 32, 0x000000008001801B, 0x0000000000000000, True,  True,  0x0000000000000000, 0x000000006EC2EDC4, 0x0000000000000000 ),
    'crc-32-cksum'             : ( 32, 0x0000000004C11DB7, 0x0000000000000000, False, False, 0x00000000FFFFFFFF, 0x00000000765E7680, 0x00000000C704DD7B ),
    'crc-32-iscsi'             : ( 32, 0x000000001EDC6F41, 0x00000000FFFFFFFF, True,  True,  0x00000000FFFFFFFF, 0x00000000E3069283, 0x00000000B798B438 ),
    'crc-32-iso-hdlc'          : ( 32, 0x0000000004C11DB7, 0x00000000FFFFFFFF, True,  True,  0x00000000FFFFFFFF, 0x00000000CBF43926, 0x00000000DEBB20E3 ),
    'crc-32-jamcrc'            : ( 32, 0x0000000004C11DB7, 0x00000000FFFFFFFF, True,  True,  0x0000000000000000, 0x00000000340BC6D9, 0x0000000000000000 ),
    'crc-32-mef'               : ( 32, 0x00000000741B8CD7, 0x00000000FFFFFFFF, True,  True,  0x0000000000000000, 0x00000000D2C22F51, 0x0000000000000000 ),
    'crc-32-mpeg-2'            : ( 32, 0x0000000004C11DB7, 0x00000000FFFFFFFF, False, False, 0x0000000000000000, 0x000000000376E6E7, 0x0000000000000000 ),
    'crc-32-xfer'              : ( 32, 0x00000000000000AF, 0x0000000000000000, False, False, 0x0000000000000000, 0x00000000BD0BE338, 0x0000000000000000 ),
    'crc-4-g-704'              : (  4, 0x0000000000000003, 0x0000000000000000, True,  True,  0x0000000000000000, 0x0000000000000007, 0x0000000000000000 ),
    'crc-4-interlaken'         : (  4, 0x0000000000000003, 0x000000000000000F, False, False, 0x000000000000000F, 0x000000000000000B, 0x0000000000000002 ),
    'crc-40-gsm'               : ( 40, 0x0000000004820009, 0x0000000000000000, False, False, 0x000000FFFFFFFFFF, 0x000000D4164FC646, 0x000000C4FF8071FF ),
    'crc-5-epc-c1g2'           : (  5, 0x0000000000000009, 0x0000000000000009, False, False, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000 ),
    'crc-5-g-704'              : (  5, 0x0000000000000015, 0x0000000000000000, True,  True,  0x0000000000000000, 0x0000000000000007, 0x0000000000000000 ),
    'crc-5-usb'                : (  5, 0x0000000000000005, 0x000000000000001F, True,  True,  0x000000000000001F, 0x0000000000000019, 0x0000000000000006 ),
    'crc-6-cdma2000-a'         : (  6, 0x0000000000000027, 0x000000000000003F, False, False, 0x0000000000000000, 0x000000000000000D, 0x0000000000000000 ),
    'crc-6-cdma2000-b'         : (  6, 0x0000000000000007, 0x000000000000003F, False, False, 0x0000000000000000, 0x000000000000003B, 0x0000000000000000 ),
    'crc-6-darc'               : (  6, 0x0000000000000019, 0x0000000000000000, True,  True,  0x0000000000000000, 0x0000000000000026, 0x0000000000000000 ),
    'crc-6-g-704'              : (  6, 0x0000000000000003, 0x0000000000000000, True,  True,  0x0000000000000000, 0x0000000000000006, 0x0000000000000000 ),
    'crc-6-gsm'                : (  6, 0x000000000000002F, 0x0000000000000000, False, False, 0x000000000000003F, 0x0000000000000013, 0x000000000000003A ),
    'crc-64-ecma-182'          : ( 64, 0x42F0E1EBA9EA3693, 0x0000000000000000, False, False, 0x0000000000000000, 0x6C40DF5F0B497347, 0x0000000000000000 ),
    'crc-64-go-iso'            : ( 64, 0x000000000000001B, 0xFFFFFFFFFFFFFFFF, True,  True,  0xFFFFFFFFFFFFFFFF, 0xB90956C775A41001, 0x5300000000000000 ),
    'crc-64-ms'                : ( 64, 0x259C84CBA6426349, 0xFFFFFFFFFFFFFFFF, True,  True,  0x0000000000000000, 0x75D4B74F024ECEEA, 0x0000000000000000 ),
    'crc-64-nvme'              : ( 64, 0xAD93D23594C93659, 0xFFFFFFFFFFFFFFFF, True,  True,  0xFFFFFFFFFFFFFFFF, 0xAE8B14860A799888, 0xF310303B2B6F6E42 ),
    'crc-64-redis'             : ( 64, 0xAD93D23594C935A9, 0x0000000000000000, True,  True,  0x0000000000000000, 0xE9C6D914C4B8D9CA, 0x0000000000000000 ),
    'crc-64-we'                : ( 64, 0x42F0E1EBA9EA3693, 0xFFFFFFFFFFFFFFFF, False, False, 0xFFFFFFFFFFFFFFFF, 0x62EC59E3F1A4F00A, 0xFCACBEBD5931A992 ),
    'crc-64-xz'                : ( 64, 0x42F0E1EBA9EA3693, 0xFFFFFFFFFFFFFFFF, True,  True,  0xFFFFFFFFFFFFFFFF, 0x995DC9BBDF1939FA, 0x49958C9ABD7D353F ),
    'crc-7-mmc'                : (  7, 0x0000000000000009, 0x0000000000000000, False, False, 0x0000000000000000, 0x0000000000000075, 0x0000000000000000 ),
    'crc-7-rohc'               : (  7, 0x000000000000004F, 0x000000000000007F, True,  True,  0x0000000000000000, 0x0000000000000053, 0x0000000000000000 ),
    'crc-7-umts'               : (  7, 0x0000000000000045, 0x0000000000000000, False, False, 0x0000000000000000, 0x0000000000000061, 0x0000000000000000 ),
    'crc-8-autosar'            : (  8, 0x000000000000002F, 0x00000000000000FF, False, False, 0x00000000000000FF, 0x00000000000000DF, 0x0000000000000042 ),
    'crc-8-bluetooth'          : (  8, 0x00000000000000A7, 0x0000000000000000, True,  True,  0x0000000000000000, 0x0000000000000026, 0x0000000000000000 ),
    'crc-8-cdma2000'           : (  8, 0x000000000000009B, 0x00000000000000FF, False, False, 0x0000000000000000, 0x00000000000000DA, 0x0000000000000000 ),
    'crc-8-darc'               : (  8, 0x0000000000000039, 0x0000000000000000, True,  True,  0x0000000000000000, 0x0000000000000015, 0x0000000000000000 ),
    'crc-8-dvb-s2'             : (  8, 0x00000000000000D5, 0x0000000000000000, False, False, 0x0000000000000000, 0x00000000000000BC, 0x0000000000000000 ),
    'crc-8-gsm-a'              : (  8, 0x000000000000001D, 0x0000000000000000, False, False, 0x0000000000000000, 0x0000000000000037, 0x0000000000000000 ),
    'crc-8-gsm-b'              : (  8, 0x0000000000000049, 0x0000000000000000, False, False, 0x00000000000000FF, 0x0000000000000094, 0x0000000000000053 ),
    'crc-8-hitag'              : (  8, 0x000000000000001D, 0x00000000000000FF, False, False, 0x0000000000000000, 0x00000000000000B4, 0x0000000000000000 ),
    'crc-8-i-432-1'            : (  8, 0x0000000000000007, 0x0000000000000000, False, False, 0x0000000000000055, 0x00000000000000A1, 0x00000000000000AC ),
    'crc-8-i-code'             : (  8, 0x000000000000001D, 0x00000000000000FD, False, False, 0x0000000000000000, 0x000000000000007E, 0x0000000000000000 ),
    'crc-8-lte'                : (  8, 0x000000000000009B, 0x0000000000000000, False, False, 0x0000000000000000, 0x00000000000000EA, 0x0000000000000000 ),
    'crc-8-maxim-dow'          : (  8, 0x0000000000000031, 0x0000000000000000, True,  True,  0x0000000000000000, 0x00000000000000A1, 0x0000000000000000 ),
    'crc-8-mifare-mad'         : (  8, 0x000000000000001D, 0x00000000000000C7, False, False, 0x0000000000000000, 0x0000000000000099, 0x0000000000000000 ),
    'crc-8-nrsc-5'             : (  8, 0x0000000000000031, 0x00000000000000FF, False, False, 0x0000000000000000, 0x00000000000000F7, 0x0000000000000000 ),
    'crc-8-opensafety'         : (  8, 0x000000000000002F, 0x0000000000000000, False, False, 0x0000000000000000, 0x000000000000003E, 0x0000000000000000 ),
    'crc-8-rohc'               : (  8, 0x0000000000000007, 0x00000000000000FF, True,  True,  0x0000000000000000, 0x00000000000000D0, 0x0000000000000000 ),
    'crc-8-sae-j1850'          : (  8, 0x000000000000001D, 0x00000000000000FF, False, False, 0x00000000000000FF, 0x000000000000004B, 0x00000000000000C4 ),
    'crc-8-smbus'              : (  8, 0x0000000000000007, 0x0000000000000000, False, False, 0x0000000000000000, 0x00000000000000F4, 0x0000000000000000 ),
    'crc-8-tech-3250'          : (  8, 0x000000000000001D, 0x00000000000000FF, True,  True,  0x0000000000000000, 0x0000000000000097, 0x0000000000000000 ),
    'crc-8-wcdma'              : (  8, 0x000000000000009B, 0x0000000000000000, True,  True,  0x0000000000000000, 0x0000000000000025, 0x0000000000000000 ),
}  # TEMPLATES

ALIASES = {
    'arc'                      : 'crc-16-arc',
    'b-crc-32'                 : 'crc-32-bzip2',
    'cksum'                    : 'crc-32-cksum',
    'crc-10'                   : 'crc-10-atm',
    'crc-10-atm'               : 'crc-10-atm',
    'crc-10-cdma2000'          : 'crc-10-cdma2000',
    'crc-10-gsm'               : 'crc-10-gsm',
    'crc-10-i-610'             : 'crc-10-atm',
    'crc-11'                   : 'crc-11-flexray',
    'crc-11-flexray'           : 'crc-11-flexray',
    'crc-11-umts'              : 'crc-11-umts',
    'crc-12-3gpp'              : 'crc-12-umts',
    'crc-12-cdma2000'          : 'crc-12-cdma2000',
    'crc-12-dect'              : 'crc-12-dect',
    'crc-12-gsm'               : 'crc-12-gsm',
    'crc-12-umts'              : 'crc-12-umts',
    'crc-13-bbc'               : 'crc-13-bbc',
    'crc-14-darc'              : 'crc-14-darc',
    'crc-14-gsm'               : 'crc-14-gsm',
    'crc-15'                   : 'crc-15-can',
    'crc-15-can'               : 'crc-15-can',
    'crc-15-mpt1327'           : 'crc-15-mpt1327',
    'crc-16'                   : 'crc-16-arc',
    'crc-16-acorn'             : 'crc-16-xmodem',
    'crc-16-arc'               : 'crc-16-arc',
    'crc-16-aug-ccitt'         : 'crc-16-spi-fujitsu',
    'crc-16-autosar'           : 'crc-16-ibm-3740',
    'crc-16-bluetooth'         : 'crc-16-kermit',
    'crc-16-buypass'           : 'crc-16-umts',
    'crc-16-ccitt'             : 'crc-16-kermit',
    'crc-16-ccitt-false'       : 'crc-16-ibm-3740',
    'crc-16-ccitt-true'        : 'crc-16-kermit',
    'crc-16-cdma2000'          : 'crc-16-cdma2000',
    'crc-16-cms'               : 'crc-16-cms',
    'crc-16-darc'              : 'crc-16-genibus',
    'crc-16-dds-110'           : 'crc-16-dds-110',
    'crc-16-dect-r'            : 'crc-16-dect-r',
    'crc-16-dect-x'            : 'crc-16-dect-x',
    'crc-16-dnp'               : 'crc-16-dnp',
    'crc-16-en-13757'          : 'crc-16-en-13757',
    'crc-16-epc'               : 'crc-16-genibus',
    'crc-16-epc-c1g2'          : 'crc-16-genibus',
    'crc-16-genibus'           : 'crc-16-genibus',
    'crc-16-gsm'               : 'crc-16-gsm',
    'crc-16-i-code'            : 'crc-16-genibus',
    'crc-16-ibm-3740'          : 'crc-16-ibm-3740',
    'crc-16-ibm-sdlc'          : 'crc-16-ibm-sdlc',
    'crc-16-iec-61158-2'       : 'crc-16-profibus',
    'crc-16-iso-hdlc'          : 'crc-16-ibm-sdlc',
    'crc-16-iso-iec-14443-3-a' : 'crc-16-iso-iec-14443-3-a',
    'crc-16-iso-iec-14443-3-b' : 'crc-16-ibm-sdlc',
    'crc-16-kermit'            : 'crc-16-kermit',
    'crc-16-lha'               : 'crc-16-arc',
    'crc-16-lj1200'            : 'crc-16-lj1200',
    'crc-16-lte'               : 'crc-16-xmodem',
    'crc-16-m17'               : 'crc-16-m17',
    'crc-16-maxim'             : 'crc-16-maxim-dow',
    'crc-16-maxim-dow'         : 'crc-16-maxim-dow',
    'crc-16-mcrf4xx'           : 'crc-16-mcrf4xx',
    'crc-16-modbus'            : 'crc-16-modbus',
    'crc-16-nrsc-5'            : 'crc-16-nrsc-5',
    'crc-16-opensafety-a'      : 'crc-16-opensafety-a',
    'crc-16-opensafety-b'      : 'crc-16-opensafety-b',
    'crc-16-profibus'          : 'crc-16-profibus',
    'crc-16-riello'            : 'crc-16-riello',
    'crc-16-spi-fujitsu'       : 'crc-16-spi-fujitsu',
    'crc-16-t10-dif'           : 'crc-16-t10-dif',
    'crc-16-teledisk'          : 'crc-16-teledisk',
    'crc-16-tms37157'          : 'crc-16-tms37157',
    'crc-16-umts'              : 'crc-16-umts',
    'crc-16-usb'               : 'crc-16-usb',
    'crc-16-v-41-lsb'          : 'crc-16-kermit',
    'crc-16-v-41-msb'          : 'crc-16-xmodem',
    'crc-16-verifone'          : 'crc-16-umts',
    'crc-16-x-25'              : 'crc-16-ibm-sdlc',
    'crc-16-xmodem'            : 'crc-16-xmodem',
    'crc-17-can-fd'            : 'crc-17-can-fd',
    'crc-21-can-fd'            : 'crc-21-can-fd',
    'crc-24'                   : 'crc-24-openpgp',
    'crc-24-ble'               : 'crc-24-ble',
    'crc-24-flexray-a'         : 'crc-24-flexray-a',
    'crc-24-flexray-b'         : 'crc-24-flexray-b',
    'crc-24-interlaken'        : 'crc-24-interlaken',
    'crc-24-lte-a'             : 'crc-24-lte-a',
    'crc-24-lte-b'             : 'crc-24-lte-b',
    'crc-24-openpgp'           : 'crc-24-openpgp',
    'crc-24-os-9'              : 'crc-24-os-9',
    'crc-3-gsm'                : 'crc-3-gsm',
    'crc-3-rohc'               : 'crc-3-rohc',
    'crc-30-cdma'              : 'crc-30-cdma',
    'crc-31-philips'           : 'crc-31-philips',
    'crc-32'                   : 'crc-32-iso-hdlc',
    'crc-32-aal5'              : 'crc-32-bzip2',
    'crc-32-adccp'             : 'crc-32-iso-hdlc',
    'crc-32-aixm'              : 'crc-32-aixm',
    'crc-32-autosar'           : 'crc-32-autosar',
    'crc-32-base91-c'          : 'crc-32-iscsi',
    'crc-32-base91-d'          : 'crc-32-base91-d',
    'crc-32-bzip2'             : 'crc-32-bzip2',
    'crc-32-castagnoli'        : 'crc-32-iscsi',
    'crc-32-cd-rom-edc'        : 'crc-32-cd-rom-edc',
    'crc-32-cksum'             : 'crc-32-cksum',
    'crc-32-dect-b'            : 'crc-32-bzip2',
    'crc-32-interlaken'        : 'crc-32-iscsi',
    'crc-32-iscsi'             : 'crc-32-iscsi',
    'crc-32-iso-hdlc'          : 'crc-32-iso-hdlc',
    'crc-32-jamcrc'            : 'crc-32-jamcrc',
    'crc-32-mef'               : 'crc-32-mef',
    'crc-32-mpeg-2'            : 'crc-32-mpeg-2',
    'crc-32-nvme'              : 'crc-32-iscsi',
    'crc-32-posix'             : 'crc-32-cksum',
    'crc-32-v-42'              : 'crc-32-iso-hdlc',
    'crc-32-xfer'              : 'crc-32-xfer',
    'crc-32-xz'                : 'crc-32-iso-hdlc',
    'crc-32c'                  : 'crc-32-iscsi',
    'crc-32d'                  : 'crc-32-base91-d',
    'crc-32q'                  : 'crc-32-aixm',
    'crc-4-g-704'              : 'crc-4-g-704',
    'crc-4-interlaken'         : 'crc-4-interlaken',
    'crc-4-itu'                : 'crc-4-g-704',
    'crc-40-gsm'               : 'crc-40-gsm',
    'crc-5-epc'                : 'crc-5-epc-c1g2',
    'crc-5-epc-c1g2'           : 'crc-5-epc-c1g2',
    'crc-5-g-704'              : 'crc-5-g-704',
    'crc-5-itu'                : 'crc-5-g-704',
    'crc-5-usb'                : 'crc-5-usb',
    'crc-6-cdma2000-a'         : 'crc-6-cdma2000-a',
    'crc-6-cdma2000-b'         : 'crc-6-cdma2000-b',
    'crc-6-darc'               : 'crc-6-darc',
    'crc-6-g-704'              : 'crc-6-g-704',
    'crc-6-gsm'                : 'crc-6-gsm',
    'crc-6-itu'                : 'crc-6-g-704',
    'crc-64'                   : 'crc-64-ecma-182',
    'crc-64-ecma-182'          : 'crc-64-ecma-182',
    'crc-64-go-ecma'           : 'crc-64-xz',
    'crc-64-go-iso'            : 'crc-64-go-iso',
    'crc-64-ms'                : 'crc-64-ms',
    'crc-64-nvme'              : 'crc-64-nvme',
    'crc-64-redis'             : 'crc-64-redis',
    'crc-64-we'                : 'crc-64-we',
    'crc-64-xz'                : 'crc-64-xz',
    'crc-7'                    : 'crc-7-mmc',
    'crc-7-mmc'                : 'crc-7-mmc',
    'crc-7-rohc'               : 'crc-7-rohc',
    'crc-7-umts'               : 'crc-7-umts',
    'crc-8'                    : 'crc-8-smbus',
    'crc-8-aes'                : 'crc-8-tech-3250',
    'crc-8-autosar'            : 'crc-8-autosar',
    'crc-8-bluetooth'          : 'crc-8-bluetooth',
    'crc-8-cdma2000'           : 'crc-8-cdma2000',
    'crc-8-darc'               : 'crc-8-darc',
    'crc-8-dvb-s2'             : 'crc-8-dvb-s2',
    'crc-8-ebu'                : 'crc-8-tech-3250',
    'crc-8-gsm-a'              : 'crc-8-gsm-a',
    'crc-8-gsm-b'              : 'crc-8-gsm-b',
    'crc-8-hitag'              : 'crc-8-hitag',
    'crc-8-i-432-1'            : 'crc-8-i-432-1',
    'crc-8-i-code'             : 'crc-8-i-code',
    'crc-8-itu'                : 'crc-8-i-432-1',
    'crc-8-lte'                : 'crc-8-lte',
    'crc-8-maxim'              : 'crc-8-maxim-dow',
    'crc-8-maxim-dow'          : 'crc-8-maxim-dow',
    'crc-8-mifare-mad'         : 'crc-8-mifare-mad',
    'crc-8-nrsc-5'             : 'crc-8-nrsc-5',
    'crc-8-opensafety'         : 'crc-8-opensafety',
    'crc-8-rohc'               : 'crc-8-rohc',
    'crc-8-sae-j1850'          : 'crc-8-sae-j1850',
    'crc-8-smbus'              : 'crc-8-smbus',
    'crc-8-tech-3250'          : 'crc-8-tech-3250',
    'crc-8-wcdma'              : 'crc-8-wcdma',
    'crc-a'                    : 'crc-16-iso-iec-14443-3-a',
    'crc-b'                    : 'crc-16-ibm-sdlc',
    'crc-ccitt'                : 'crc-16-kermit',
    'crc-ibm'                  : 'crc-16-arc',
    'dow-crc'                  : 'crc-8-maxim-dow',
    'jamcrc'                   : 'crc-32-jamcrc',
    'kermit'                   : 'crc-16-kermit',
    'modbus'                   : 'crc-16-modbus',
    'pkzip'                    : 'crc-32-iso-hdlc',
    'r-crc-16'                 : 'crc-16-dect-r',
    'x-25'                     : 'crc-16-ibm-sdlc',
    'x-crc-12'                 : 'crc-12-dect',
    'x-crc-16'                 : 'crc-16-dect-x',
    'xfer'                     : 'crc-32-xfer',
    'xmodem'                   : 'crc-16-xmodem',
    'zmodem'                   : 'crc-16-xmodem',
}  # ALIASES

NAME_DEFAULT = 'crc-32'

NAME = 'crc-12-umts'  # a strange one
CONFIG = Config(*TEMPLATES[NAME])


def int_to_hex(value: int, width: int, byteorder: str = 'big') -> str:
    size = (width + 7) // 8
    hexstr = value.to_bytes(size, byteorder=byteorder).hex()
    return hexstr


class ModuleTests(unittest.TestCase):

    def test_constants(self):
        self.assertGreater(_crc.BYTE_WIDTH, 0)
        self.assertGreater(_crc.MAX_WIDTH, 0)
        self.assertGreaterEqual(_crc.MAX_WIDTH, _crc.BYTE_WIDTH)
        self.assertEqual(_crc.MAX_VALUE, (1 << _crc.MAX_WIDTH) - 1)

    def test_templates_available(self):
        actual = _crc.templates_available()
        expected = {k: TEMPLATES[ALIASES[k]][:6] for k in ALIASES}
        self.assertEqual(len(actual), len(expected))
        actual_keys = list(sorted(actual.keys()))
        expected_keys = list(sorted(expected.keys()))
        self.assertEqual(actual_keys, expected_keys)
        actual_values = [actual[k] for k in actual_keys]
        expected_values = [expected[k] for k in expected_keys]
        self.assertEqual(actual_values, expected_values)


class TemplateTests(unittest.TestCase):

    def test_templates_available(self):
        names = _crc.templates_available()
        for index, (alias, name) in enumerate(ALIASES.items()):
            with self.subTest(index=index, name=name, alias=alias):
                name_ref = TEMPLATES[name][:6]
                name_crc = names[alias]
                self.assertEqual(name_crc, name_ref)

    def _check_init(self, crc, config: Config):
        self.assertIsNotNone(config)
        self.assertIsNotNone(crc)

        fmt = f'0b{{0:0{config.width}b}}'.format
        self.assertEqual(crc.width,  config.width)
        self.assertEqual(crc.poly,   config.poly,   f'{fmt(crc.poly)} != {fmt(config.poly)}')
        self.assertEqual(crc.init,   config.init,   f'{fmt(crc.init)} != {fmt(config.init)}')
        self.assertEqual(crc.refin,  config.refin)
        self.assertEqual(crc.refout, config.refout)
        self.assertEqual(crc.xorout, config.xorout, f'{fmt(crc.xorout)} != {fmt(config.xorout)}')
        self.assertEqual(int(crc),   config.init,   f'{fmt(int(crc))} != {fmt(config.init)}')

    def _check_result(self, crc, config: Config):
        self.assertIsNotNone(config)
        self.assertIsNotNone(crc)
        bytesize = (config.width + BYTE_WIDTH - 1) // BYTE_WIDTH
        self.assertGreater(bytesize, 0)
        result = config.check

        fmt = f'0b{{0:0{config.width}b}}'.format
        self.assertEqual(crc.width,  config.width)
        self.assertEqual(crc.poly,   config.poly,   f'{fmt(crc.poly)} != {fmt(config.poly)}')
        self.assertEqual(crc.init,   config.init,   f'{fmt(crc.init)} != {fmt(config.init)}')
        self.assertEqual(crc.refin,  config.refin)
        self.assertEqual(crc.refout, config.refout)
        self.assertEqual(crc.xorout, config.xorout, f'{fmt(crc.xorout)} != {fmt(config.xorout)}')
        self.assertEqual(int(crc),   result,        f'{fmt(int(crc))} != {fmt(result)}')

        digest_big = result.to_bytes(bytesize, 'big')
        self.assertEqual(crc.digest(), digest_big)

        hexdigest_big = int_to_hex(result, config.width, 'big')
        self.assertEqual(crc.hexdigest(), hexdigest_big)

    def test_init(self):
        for index, (name, args) in enumerate(TEMPLATES.items()):
            config = Config(*args)
            with self.subTest(index=index, name=name, config=config):
                crc = _crc.crc(name=name)
                self._check_init(crc, config)
                crc.clear(config.init)
                self._check_init(crc, config)

    def test_update_word(self):
        for index, (name, args) in enumerate(TEMPLATES.items()):
            config = Config(*args)
            with self.subTest(index=index, name=name, config=config):
                crc = _crc.crc(name=name)
                for word in DATA:
                    crc.update_word(word, BYTE_WIDTH)
                self._check_result(crc, config)
                crc.clear()
                for word in DATA:
                    crc.update_word(word, BYTE_WIDTH)
                self._check_result(crc, config)
                crc.clear(config.init)
                for word in DATA:
                    crc.update_word(word, BYTE_WIDTH)
                self._check_result(crc, config)

    def test_update(self):
        for index, (name, args) in enumerate(TEMPLATES.items()):
            config = Config(*args)
            with self.subTest(index=index, name=name, config=config):
                crc = _crc.crc(name=name)
                crc.update(DATA)
                self._check_result(crc, config)
                crc.clear()
                crc.update(DATA)
                self._check_result(crc, config)
                crc.clear(config.init)
                crc.update(DATA)
                self._check_result(crc, config)

    def test_update_bytes(self):
        for index, (name, args) in enumerate(TEMPLATES.items()):
            config = Config(*args)
            with self.subTest(index=index, name=name, config=config):
                crc = _crc.crc(name=name, method='bitwise')
                crc.update(DATA)
                self._check_result(crc, config)
                crc.clear()
                crc.update(DATA)
                self._check_result(crc, config)
                crc.clear(config.init)
                crc.update(DATA)
                self._check_result(crc, config)

    def test_update_bytewise(self):
        for index, (name, args) in enumerate(TEMPLATES.items()):
            config = Config(*args)
            with self.subTest(index=index, name=name, config=config):
                crc = _crc.crc(name=name, method='bytewise')
                crc.update(DATA)
                self._check_result(crc, config)
                crc.clear()
                crc.update(DATA)
                self._check_result(crc, config)
                crc.clear(config.init)
                crc.update(DATA)
                self._check_result(crc, config)

    def test_update_wordwise(self):
        for index, (name, args) in enumerate(TEMPLATES.items()):
            config = Config(*args)
            with self.subTest(index=index, name=name, config=config):
                crc = _crc.crc(name=name, method='wordwise')
                crc.update(DATA)
                self._check_result(crc, config)
                crc.clear()
                crc.update(DATA)
                self._check_result(crc, config)
                crc.clear(config.init)
                crc.update(DATA)
                self._check_result(crc, config)

    def test_update_bytewise_single(self):
        buffer = bytearray(1)
        for index, (name, args) in enumerate(TEMPLATES.items()):
            config = Config(*args)
            fmt = f'0b{{0:0{config.width}b}}'.format
            with self.subTest(index=index, name=name, config=config):
                crc = _crc.crc(name=name, method='bytewise')
                for byte in range(256):
                    crc.clear()
                    crc.update_word(byte, BYTE_WIDTH)
                    result_bits = int(crc)
                    crc.clear()
                    buffer[0] = byte
                    crc.update(buffer)
                    result_table = int(crc)
                    self.assertEqual(result_table, result_bits, f'{fmt(result_table)} != {fmt(result_bits)}')

    def test_update_wordwise_single(self):
        buffer = bytearray(1)
        for index, (name, args) in enumerate(TEMPLATES.items()):
            config = Config(*args)
            fmt = f'0b{{0:0{config.width}b}}'.format
            with self.subTest(index=index, name=name, config=config):
                crc = _crc.crc(name=name, method='wordwise')
                for byte in range(BYTE_COUNT):
                    crc.clear()
                    crc.update_word(byte, BYTE_WIDTH)
                    result_bits = int(crc)
                    crc.clear()
                    buffer[0] = byte
                    crc.update(buffer)
                    result_table = int(crc)
                    self.assertEqual(result_table, result_bits, f'{fmt(result_table)} != {fmt(result_bits)}')

    def test_combine(self):
        for index, (name, args) in enumerate(TEMPLATES.items()):
            config = Config(*args)
            fmt = f'0b{{0:0{config.width}b}}'.format
            with self.subTest(index=index, name=name, config=config):
                a = _crc.crc(DATA, name=name)
                b = _crc.crc(DATA2, name=name)
                c = _crc.crc(DATA + DATA2, name=name)
                actual = a.combine(int(a), int(b), len(DATA2))
                expected = int(c)
                self.assertEqual(actual, expected, f'{fmt(actual)} != {fmt(expected)}')


class CtorTests(unittest.TestCase):

    def test_noargs(self):
        crc = _crc.crc()
        config = Config(*TEMPLATES[ALIASES[NAME_DEFAULT]])

        self.assertEqual(crc.width,  config.width)
        self.assertEqual(crc.poly,   config.poly)
        self.assertEqual(crc.init,   config.init)
        self.assertEqual(crc.refin,  config.refin)
        self.assertEqual(crc.refout, config.refout)
        self.assertEqual(crc.xorout, config.xorout)
        self.assertEqual(int(crc),   config.init)

    def test_noargs_data(self):
        crc = _crc.crc(DATA)
        actual = int(crc)
        expected = zlib.crc32(DATA)
        fmt = '0b{0:032b}'.format
        self.assertEqual(actual, expected, f'{fmt(actual)} != {fmt(expected)}')

    def test_data(self):
        _crc.crc(DATA, name=NAME)
        _crc.crc(bytes(DATA), name=NAME)
        _crc.crc(bytearray(DATA), name=NAME)
        _crc.crc(memoryview(DATA), name=NAME)

        with self.assertRaises(TypeError):
            _crc.crc(0, name=NAME)
        with self.assertRaises(TypeError):
            _crc.crc('123456789', name=NAME)
        with self.assertRaises(TypeError):
            _crc.crc(object(), name=NAME)

    def test_name(self):
        _crc.crc(name=NAME)

        with self.assertRaises(TypeError):
            _crc.crc(name=1)
        with self.assertRaises(TypeError):
            _crc.crc(name=NAME.encode())
        with self.assertRaises(KeyError):
            _crc.crc(name='unknown')

    def test_width(self):
        crc = _crc.crc(name=NAME, width=None)
        self.assertEqual(crc.width, CONFIG.width)
        crc = _crc.crc(width=1, poly=1)
        self.assertEqual(crc.width, 1)
        crc = _crc.crc(width=MAX_WIDTH, poly=1)
        self.assertEqual(crc.width, MAX_WIDTH)

        with self.assertRaises(TypeError):
            _crc.crc(width='1', poly=1)
        with self.assertRaises(TypeError):
            _crc.crc(width=b'1', poly=1)
        with self.assertRaises(OverflowError):
            _crc.crc(width=-1, poly=1)
        with self.assertRaises(OverflowError):
            _crc.crc(width=0, poly=1)
        with self.assertRaises(OverflowError):
            _crc.crc(width=MAX_WIDTH+1, poly=1)

    def test_poly(self):
        crc = _crc.crc(name=NAME, poly=None)
        self.assertEqual(crc.poly, CONFIG.poly)
        crc = _crc.crc(width=MAX_WIDTH, poly=1)
        self.assertEqual(crc.poly, 1)
        crc = _crc.crc(width=MAX_WIDTH, poly=MAX_VALUE)
        self.assertEqual(crc.poly, MAX_VALUE)

        with self.assertRaises(TypeError):
            _crc.crc(width=MAX_WIDTH, poly='1')
        with self.assertRaises(TypeError):
            _crc.crc(width=MAX_WIDTH, poly=b'1')
        with self.assertRaises(OverflowError):
            _crc.crc(width=MAX_WIDTH, poly=-1)
        with self.assertRaises(OverflowError):
            _crc.crc(width=MAX_WIDTH, poly=0)
        with self.assertRaises(OverflowError):
            _crc.crc(width=MAX_WIDTH, poly=MAX_VALUE+1)
        with self.assertRaises(OverflowError):
            _crc.crc(width=1, poly=2)

    def test_init(self):
        crc = _crc.crc(name=NAME, init=None)
        self.assertEqual(crc.init, CONFIG.init)
        crc = _crc.crc(width=MAX_WIDTH, poly=1, init=0)
        self.assertEqual(crc.init, 0)
        crc = _crc.crc(width=MAX_WIDTH, poly=1, init=MAX_VALUE)
        self.assertEqual(crc.init, MAX_VALUE)

        with self.assertRaises(TypeError):
            _crc.crc(width=MAX_WIDTH, poly=1, init='1')
        with self.assertRaises(TypeError):
            _crc.crc(width=MAX_WIDTH, poly=1, init=b'1')
        with self.assertRaises(OverflowError):
            _crc.crc(width=MAX_WIDTH, poly=1, init=-1)
        with self.assertRaises(OverflowError):
            _crc.crc(width=MAX_WIDTH, poly=1, init=MAX_VALUE+1)
        with self.assertRaises(OverflowError):
            _crc.crc(width=1, poly=1, init=2)

    def test_refin(self):
        crc = _crc.crc(name=NAME, refin=True)
        self.assertTrue(crc.refin)
        crc = _crc.crc(name=NAME, refin=False)
        self.assertFalse(crc.refin)

    def test_refout(self):
        crc = _crc.crc(name=NAME, refout=True)
        self.assertTrue(crc.refout)
        crc = _crc.crc(name=NAME, refout=False)
        self.assertFalse(crc.refout)

    def test_xorout(self):
        crc = _crc.crc(name=NAME, xorout=None)
        self.assertEqual(crc.xorout, CONFIG.xorout)
        crc = _crc.crc(width=MAX_WIDTH, poly=1, xorout=0)
        self.assertEqual(crc.xorout, 0)
        crc = _crc.crc(width=MAX_WIDTH, poly=1, xorout=MAX_VALUE)
        self.assertEqual(crc.xorout, MAX_VALUE)

        with self.assertRaises(TypeError):
            _crc.crc(width=MAX_WIDTH, poly=1, xorout='1')
        with self.assertRaises(TypeError):
            _crc.crc(width=MAX_WIDTH, poly=1, xorout=b'1')
        with self.assertRaises(OverflowError):
            _crc.crc(width=MAX_WIDTH, poly=1, xorout=MAX_VALUE+1)
        with self.assertRaises(OverflowError):
            _crc.crc(width=MAX_WIDTH, poly=1, xorout=-1)
        with self.assertRaises(OverflowError):
            _crc.crc(width=1, poly=1, xorout=2)

    def test_method(self):
        _crc.crc(name=NAME)
        _crc.crc(name=NAME, method='bitwise')
        _crc.crc(name=NAME, method='bytewise')
        _crc.crc(name=NAME, method='wordwise')

        with self.assertRaises(TypeError):
            _crc.crc(width=MAX_WIDTH, poly=1, method=1)
        with self.assertRaises(TypeError):
            _crc.crc(width=MAX_WIDTH, poly=1, method=b'1')
        with self.assertRaises(KeyError):
            _crc.crc(width=MAX_WIDTH, poly=1, method='unknown')

    def test_usedforsecurity(self):
        _crc.crc(name=NAME, usedforsecurity=False)
        _crc.crc(name=NAME, usedforsecurity=True)

    def test_getters(self):
        crc = _crc.crc(name=NAME)

        self.assertEqual(crc.digest_size, MAX_SIZE)
        self.assertEqual(crc.block_size,  1)
        self.assertEqual(crc.name,        'crc')

        self.assertEqual(crc.width,  CONFIG.width)
        self.assertEqual(crc.poly,   CONFIG.poly)
        self.assertEqual(crc.init,   CONFIG.init)
        self.assertEqual(crc.refin,  CONFIG.refin)
        self.assertEqual(crc.refout, CONFIG.refout)
        self.assertEqual(crc.xorout, CONFIG.xorout)
        self.assertEqual(int(crc),   CONFIG.init)


class MethodsTests(unittest.TestCase):

    def test___index__(self):
        crc = _crc.crc(DATA, name=NAME)
        self.assertEqual(crc.__index__(), CONFIG.check)
        self.assertEqual(int(crc), CONFIG.check)

    def test_combine(self):
        a = _crc.crc(DATA, name=NAME)
        b = _crc.crc(DATA2, name=NAME)
        c = _crc.crc(DATA + DATA2, name=NAME)
        crc1 = int(a)
        crc2 = int(b)
        len2 = len(DATA2)
        actual = a.combine(crc1, crc2, len2)
        expected = int(c)
        fmt = f'0b{{0:0{a.width}b}}'.format
        self.assertEqual(actual, expected, f'{fmt(actual)} != {fmt(expected)}')

        actual = a.combine(crc1, crc2, 0)
        expected = crc1
        self.assertEqual(actual, expected, f'{fmt(actual)} != {fmt(expected)}')

        with self.assertRaises(ValueError):
            a.combine(-1, crc2, len2)
        with self.assertRaises(OverflowError):
            a.combine(MAX_VALUE, crc2, len2)
        with self.assertRaises(OverflowError):
            a.combine(MAX_VALUE+1, crc2, len2)
        with self.assertRaises(ValueError):
            a.combine(crc1, -1, len2)
        with self.assertRaises(OverflowError):
            a.combine(crc1, MAX_VALUE, len2)
        with self.assertRaises(OverflowError):
            a.combine(crc1, MAX_VALUE+1, len2)
        with self.assertRaises(ValueError):
            a.combine(crc1, crc2, -1)

    def test_copy(self):
        a = _crc.crc(DATA, name=NAME)
        b = a.copy()
        self.assertIsNot(a, b)
        self.assertEqual(a.width,  b.width)
        self.assertEqual(a.poly,   b.poly)
        self.assertEqual(a.init,   b.init)
        self.assertEqual(a.refin,  b.refin)
        self.assertEqual(a.refout, b.refout)
        self.assertEqual(a.xorout, b.xorout)
        self.assertEqual(int(a),   int(b))

    def test_digest(self):
        size = (CONFIG.width + BYTE_WIDTH - 1) // BYTE_WIDTH
        digest = CONFIG.check.to_bytes(size, 'big')
        crc = _crc.crc(DATA, name=NAME)
        self.assertEqual(crc.digest(), digest)

    def test_hexdigest(self):
        hexdigest = int_to_hex(CONFIG.check, CONFIG.width, 'big')
        crc = _crc.crc(DATA, name=NAME)
        self.assertEqual(crc.hexdigest(), hexdigest)

    def test_clear_noargs(self):
        crc = _crc.crc(DATA, name=NAME)
        self.assertNotEqual(int(crc), crc.init)
        crc.clear()
        self.assertEqual(int(crc), crc.init)

    def test_clear_init(self):
        for xorout in (0, 1):
            crc = _crc.crc(width=MAX_WIDTH, poly=1, init=1, xorout=xorout)
            self.assertEqual(int(crc), 1)
            crc.clear(0)
            self.assertEqual(int(crc), 0)
            crc.clear(MAX_VALUE)
            self.assertEqual(int(crc), MAX_VALUE)
            crc.clear(None)
            self.assertEqual(int(crc), 1)
            crc.clear()
            self.assertEqual(int(crc), 1)

        with self.assertRaises(TypeError):
            crc.clear('1')
        with self.assertRaises(TypeError):
            crc.clear(b'1')
        with self.assertRaises(OverflowError):
            crc.clear(-1)
        with self.assertRaises(OverflowError):
            crc.clear(MAX_VALUE+1)

    def test_update(self):
        crc = _crc.crc(name=NAME)
        self.assertEqual(int(crc), CONFIG.init)
        crc.update(b'')
        self.assertEqual(int(crc), CONFIG.init)
        crc.update(DATA)
        self.assertEqual(int(crc), CONFIG.check)
        crc.clear()
        crc.update(bytes(DATA))
        self.assertEqual(int(crc), CONFIG.check)
        crc.clear()
        crc.update(bytearray(DATA))
        self.assertEqual(int(crc), CONFIG.check)
        crc.clear()
        crc.update(memoryview(DATA))
        self.assertEqual(int(crc), CONFIG.check)

        with self.assertRaises(TypeError):
            crc.update(object())
        with self.assertRaises(TypeError):
            crc.update('1')
        with self.assertRaises(TypeError):
            crc.update(1)
        with self.assertRaises(TypeError):
            crc.update(-1)

    def test_update_word(self):
        crc = _crc.crc(name=NAME)
        self.assertEqual(int(crc), CONFIG.init)
        crc.update_word(0, 0)
        self.assertEqual(int(crc), CONFIG.init)
        crc.update_word(1, 0)
        self.assertEqual(int(crc), CONFIG.init)
        for byte in DATA:
            crc.update_word(byte, BYTE_WIDTH)
        self.assertEqual(int(crc), CONFIG.check)

        crc = _crc.crc(width=MAX_WIDTH, poly=1)
        crc.update_word(0, 0)
        crc.update_word(0, MAX_WIDTH)

        with self.assertRaises(TypeError):
            crc.update_word(object(), BYTE_WIDTH)
        with self.assertRaises(TypeError):
            crc.update_word('1', BYTE_WIDTH)
        with self.assertRaises(OverflowError):
            crc.update_word(0, -1)
        with self.assertRaises(ValueError):
            crc.update_word(-1, BYTE_WIDTH)
        with self.assertRaises(OverflowError):
            crc.update_word(0, MAX_WIDTH+1)

    def test_zero_bits(self):
        crc = _crc.crc(name=NAME)
        self.assertEqual(int(crc), CONFIG.init)
        crc.zero_bits(0)
        self.assertEqual(int(crc), CONFIG.init)
        crc.zero_bits(1)
        self.assertEqual(int(crc), CONFIG.init)
        crc.update(DATA)
        self.assertEqual(int(crc), CONFIG.check)
        ref = crc.copy()
        crc.zero_bits(1)
        ref.update_word(0, 1)
        self.assertEqual(int(crc), int(ref))
        crc.zero_bits(CONFIG.width)
        ref.update_word(0, CONFIG.width)
        self.assertEqual(int(crc), int(ref))
        self.assertNotEqual(int(crc), CONFIG.check)

        crc = _crc.crc(width=MAX_WIDTH, poly=1)
        crc.zero_bits(0)

        with self.assertRaises(TypeError):
            crc.zero_bits(object())
        with self.assertRaises(TypeError):
            crc.zero_bits('1')
        with self.assertRaises(ValueError):
            crc.zero_bits(-1)
        with self.assertRaises(OverflowError):
            crc.zero_bits(MAX_VALUE+1)

    def test_zero_bytes(self):
        crc = _crc.crc(name=NAME)
        self.assertEqual(int(crc), CONFIG.init)
        crc.zero_bytes(0)
        self.assertEqual(int(crc), CONFIG.init)
        crc.zero_bytes(1)
        self.assertEqual(int(crc), CONFIG.init)
        crc.update(DATA)
        self.assertEqual(int(crc), CONFIG.check)
        ref = crc.copy()
        crc.zero_bytes(1)
        ref.update(b'\0')
        self.assertEqual(int(crc), int(ref))
        self.assertNotEqual(int(crc), CONFIG.check)

        crc = _crc.crc(width=MAX_WIDTH, poly=1)
        crc.zero_bytes(0)

        with self.assertRaises(TypeError):
            crc.zero_bytes(object())
        with self.assertRaises(TypeError):
            crc.zero_bytes('1')
        with self.assertRaises(ValueError):
            crc.zero_bytes(-1)
        with self.assertRaises(OverflowError):
            crc.zero_bytes(MAX_VALUE+1)


class PepExamplesTests(unittest.TestCase):

    def test_common_operations(self):
        crc = hashlib.crc(b'123456789', name='crc-16-ccitt-false')
        self.assertEqual(int(crc), 10673)
        self.assertEqual(hex(crc), '0x29b1')
        self.assertEqual(crc.digest(), b')\xb1')
        self.assertEqual(crc.digest()[::-1], b'\xb1)')
        self.assertEqual(crc.hexdigest(), '29b1')
        crc.update(b'abcdef')
        self.assertEqual(hex(crc), '0xc378')
        crc.clear(0x29b1)
        crc.update(b'abcdef')
        self.assertEqual(hex(crc), '0xc378')
        crc.clear()
        self.assertEqual(hex(crc), '0xffff')
        crc.update(b'123456789')
        self.assertEqual(hex(crc), '0x29b1')

    def test_custom_crc(self):
        crc = hashlib.crc(width=16, poly=0x1021, init=0xFFFF)
        self.assertEqual(hex(crc), '0xffff')
        crc.update(b'123456789')
        self.assertEqual(hex(crc), '0x29b1')

    def test_combining_two_crcs(self):
        name = 'crc-16-ccitt-false'
        ref = hex(hashlib.crc(b'123456789abcdef', name=name))
        crc1 = int(hashlib.crc(b'123456789', name=name))
        self.assertEqual(hex(crc1), '0x29b1')
        crc2 = int(hashlib.crc(b'abcdef', name=name))
        self.assertEqual(hex(crc2), '0x34ed')
        crc12 = hashlib.crc(name=name).combine(crc1, crc2, len(b'abcdef'))
        self.assertEqual(hex(crc12), '0xc378')
        self.assertEqual(hex(crc12), ref)


if __name__ == '__main__':
    unittest.main()
