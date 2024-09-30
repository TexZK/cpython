/* CRC module */

/* This module provides a native implementation of CRC algorithms */

/*
   Copyright (C) 2024   Andrea Zoppi (texzk@email.it)
   Licensed to PSF under a Contributor Agreement.
*/

/* CRC objects */

#ifndef Py_BUILD_CORE_BUILTIN
#  define Py_BUILD_CORE_MODULE 1
#endif

#include "Python.h"
#include "pycore_pylifecycle.h"
#include "pycore_global_objects.h"  /* _Py_ID */
#include "pycore_unicodeobject.h"   /* _PyUnicode_Equal */

#include <stdbool.h>                /* used by hashlib macros */
#include <stdint.h>                 /* guaranteed widths */

#include "hashlib.h"


/*[clinic input]
module _crc
class _crc.crcu64  "crcu64object *"  "(crcmodule_get_state()->crcu64_type)"
[clinic start generated code]*/
/*[clinic end generated code: output=da39a3ee5e6b4b0d input=c57f99c9c63f7cdc]*/


/* ---------------------------------------------------------------- */
/* Error handling helper macros */

/* Checks a generic expression; error if NULL */
#define CHECK(EXPR)         \
    do {                    \
        if (!(EXPR)) {      \
            goto error;     \
        }                   \
    } while (0)          /**/


/* Checks an crc_u64 result; error if -1 and exception active */
#define CHECK_U64(EXPR)                                         \
    do {                                                        \
        if (((EXPR) == (crc_u64)-1LL) && PyErr_Occurred()) {    \
            goto error;                                         \
        }                                                       \
    } while (0)                                              /**/


/* ================================================================ */
/* Integer type shortcuts for CRC algorithms */

typedef uint_least8_t   crc_u8;
typedef uint_fast16_t   crc_u16;
typedef uint_fast32_t   crc_u32;
typedef uint_fast64_t   crc_u64;

#define CRC_U8_WIDTH    CHAR_BIT
#define CRC_U16_LEAST   16
#define CRC_U32_LEAST   32
#define CRC_U64_LEAST   64
#define CRC_MAX_WIDTH   CRC_U64_LEAST
#define CRC_MAX_SIZE    ((CRC_MAX_WIDTH + (CRC_U8_WIDTH - 1)) / CRC_U8_WIDTH)

#define CRC_U8_COUNT    ((crc_u16)1 << CRC_U8_WIDTH)
#define CRC_U8_MASK     ((crc_u8)(CRC_U8_COUNT - 1))
#define CRC_U8_NIBBLE   ((CRC_U8_WIDTH  + (4 - 1)) / 4)
#define CRC_MAX_NIBBLE  ((CRC_MAX_WIDTH + (4 - 1)) / 4)

#define CRC_U32_TOP     ((crc_u32)1 << (CRC_U32_LEAST - 1))
#define CRC_U64_TOP     ((crc_u64)1 << (CRC_U64_LEAST - 1))

#define CRC_METHOD_BITWISE  0
#define CRC_METHOD_BYTEWISE 1
#define CRC_METHOD_WORDWISE 2

#define CRC_NAME_DEFAULT    "crc-32"


/* ---------------------------------------------------------------- */
/* Generic helper functions */

static inline crc_u8
is_little_endian(void)
{
    const crc_u32 little_endian_ = 1;
    crc_u8 little_endian = *(const crc_u8 *)&little_endian_;
    return little_endian;
}


/* Calculates the bit mask with the given width; LSb-aligned */
static inline crc_u64
crc_u64_bitmask(crc_u8 width)
{
    assert(width <= CRC_MAX_WIDTH);
#if ((CRC_U8_WIDTH == 8) && (CRC_MAX_WIDTH == 64))
    return (crc_u64)(0xFFFFFFFFFFFFFFFFuLL >> (CRC_MAX_WIDTH - width));
#else
    return ((((crc_u64)1 << (width - 1)) - 1) << 1) | 1;
#endif
}


/* Reverses the bits of a word of width bits; LSb-aligned */
static crc_u64
crc_u64_bitswap(crc_u64 word, crc_u8 width)
{
    assert(width <= CRC_MAX_WIDTH);
#if ((CRC_U8_WIDTH == 8) && (CRC_MAX_WIDTH == 64))
    word = (((word << 32) & 0xFFFFFFFF00000000uLL) |
            ((word >> 32) & 0x00000000FFFFFFFFuLL));
    word = (((word << 16) & 0xFFFF0000FFFF0000uLL) |
            ((word >> 16) & 0x0000FFFF0000FFFFuLL));
    word = (((word <<  8) & 0xFF00FF00FF00FF00uLL) |
            ((word >>  8) & 0x00FF00FF00FF00FFuLL));
    word = (((word <<  4) & 0xF0F0F0F0F0F0F0F0uLL) |
            ((word >>  4) & 0x0F0F0F0F0F0F0F0FuLL));
    word = (((word <<  2) & 0xCCCCCCCCCCCCCCCCuLL) |
            ((word >>  2) & 0x3333333333333333uLL));
    word = (((word <<  1) & 0xAAAAAAAAAAAAAAAAuLL) |
            ((word >>  1) & 0x5555555555555555uLL));
    return word >> (64 - width);
#else
    crc_u64 y = 0;
    while (width--) {
        y <<= 1;
        y |= x & 1;
        x >>= 1;
    }
    return y;
#endif
}


/* Reverses the bytes of a word of maximum CRC size; LSb-aligned */
static crc_u64
crc_u64_byteswap(crc_u64 word)
{
#if ((CRC_U8_WIDTH == 8) && (CRC_MAX_WIDTH == 64))
    word = (((word << 32) & 0xFFFFFFFF00000000uLL) |
            ((word >> 32) & 0x00000000FFFFFFFFuLL));
    word = (((word << 16) & 0xFFFF0000FFFF0000uLL) |
            ((word >> 16) & 0x0000FFFF0000FFFFuLL));
    word = (((word <<  8) & 0xFF00FF00FF00FF00uLL) |
            ((word >>  8) & 0x00FF00FF00FF00FFuLL));
    return word;
#else
    crc_u64 y = 0;
    for (crc_u16 i = CRC_MAX_SIZE; i--; /**/) {
        y <<= CRC_U8_WIDTH;
        y |= x & CRC_U8_MASK;
        x >>= CRC_U8_WIDTH;
    }
    return y;
#endif
}


/* ---------------------------------------------------------------- */

/* Please keep sorted in increasing lexicographic order! */
typedef enum {
    crc_id_3_gsm = 0,
    crc_id_3_rohc,
    crc_id_4_g_704,
    crc_id_4_interlaken,
    crc_id_5_epc_c1g2,
    crc_id_5_g_704,
    crc_id_5_usb,
    crc_id_6_cdma2000_a,
    crc_id_6_cdma2000_b,
    crc_id_6_darc,
    crc_id_6_g_704,
    crc_id_6_gsm,
    crc_id_7_mmc,
    crc_id_7_rohc,
    crc_id_7_umts,
    crc_id_8_autosar,
    crc_id_8_bluetooth,
    crc_id_8_cdma2000,
    crc_id_8_darc,
    crc_id_8_dvb_s2,
    crc_id_8_gsm_a,
    crc_id_8_gsm_b,
    crc_id_8_hitag,
    crc_id_8_i_432_1,
    crc_id_8_i_code,
    crc_id_8_lte,
    crc_id_8_maxim_dow,
    crc_id_8_mifare_mad,
    crc_id_8_nrsc_5,
    crc_id_8_opensafety,
    crc_id_8_rohc,
    crc_id_8_sae_j1850,
    crc_id_8_smbus,
    crc_id_8_tech_3250,
    crc_id_8_wcdma,
    crc_id_10_atm,
    crc_id_10_cdma2000,
    crc_id_10_gsm,
    crc_id_11_flexray,
    crc_id_11_umts,
    crc_id_12_cdma2000,
    crc_id_12_dect,
    crc_id_12_gsm,
    crc_id_12_umts,
    crc_id_13_bbc,
    crc_id_14_darc,
    crc_id_14_gsm,
    crc_id_15_can,
    crc_id_15_mpt1327,
    crc_id_16_arc,
    crc_id_16_cdma2000,
    crc_id_16_cms,
    crc_id_16_dds_110,
    crc_id_16_dect_r,
    crc_id_16_dect_x,
    crc_id_16_dnp,
    crc_id_16_en_13757,
    crc_id_16_genibus,
    crc_id_16_gsm,
    crc_id_16_ibm_3740,
    crc_id_16_ibm_sdlc,
    crc_id_16_iso_iec_14443_3_a,
    crc_id_16_kermit,
    crc_id_16_lj1200,
    crc_id_16_m17,
    crc_id_16_maxim_dow,
    crc_id_16_mcrf4xx,
    crc_id_16_modbus,
    crc_id_16_nrsc_5,
    crc_id_16_opensafety_a,
    crc_id_16_opensafety_b,
    crc_id_16_profibus,
    crc_id_16_riello,
    crc_id_16_spi_fujitsu,
    crc_id_16_t10_dif,
    crc_id_16_teledisk,
    crc_id_16_tms37157,
    crc_id_16_umts,
    crc_id_16_usb,
    crc_id_16_xmodem,
    crc_id_17_can_fd,
    crc_id_21_can_fd,
    crc_id_24_ble,
    crc_id_24_flexray_a,
    crc_id_24_flexray_b,
    crc_id_24_interlaken,
    crc_id_24_lte_a,
    crc_id_24_lte_b,
    crc_id_24_openpgp,
    crc_id_24_os_9,
    crc_id_30_cdma,
    crc_id_31_philips,
    crc_id_32_aixm,
    crc_id_32_autosar,
    crc_id_32_base91_d,
    crc_id_32_bzip2,
    crc_id_32_cd_rom_edc,
    crc_id_32_cksum,
    crc_id_32_iscsi,
    crc_id_32_iso_hdlc,
    crc_id_32_jamcrc,
    crc_id_32_mef,
    crc_id_32_mpeg_2,
    crc_id_32_xfer,
    crc_id_40_gsm,
    crc_id_64_ecma_182,
    crc_id_64_go_iso,
    crc_id_64_ms,
    crc_id_64_nvme,
    crc_id_64_redis,
    crc_id_64_we,
    crc_id_64_xz,
    crc_id_count  /* sentinel */
} crc_id;


/* name:id mapping */
typedef struct {
    const char *name;
    crc_id id;
} crc_name_id;


/*
  Please keep sorted in increasing ASCII order!

  Names from:  https://reveng.sourceforge.io/crc-catalogue/
  (converted to lowercase and separated by hyphens only)
*/
static const crc_name_id crc_name_ids[] = {
    { "arc"                      , crc_id_16_arc               },
    { "b-crc-32"                 , crc_id_32_bzip2             },
    { "cksum"                    , crc_id_32_cksum             },
    { "crc-10"                   , crc_id_10_atm               },
    { "crc-10-atm"               , crc_id_10_atm               },
    { "crc-10-cdma2000"          , crc_id_10_cdma2000          },
    { "crc-10-gsm"               , crc_id_10_gsm               },
    { "crc-10-i-610"             , crc_id_10_atm               },
    { "crc-11"                   , crc_id_11_flexray           },
    { "crc-11-flexray"           , crc_id_11_flexray           },
    { "crc-11-umts"              , crc_id_11_umts              },
    { "crc-12-3gpp"              , crc_id_12_umts              },
    { "crc-12-cdma2000"          , crc_id_12_cdma2000          },
    { "crc-12-dect"              , crc_id_12_dect              },
    { "crc-12-gsm"               , crc_id_12_gsm               },
    { "crc-12-umts"              , crc_id_12_umts              },
    { "crc-13-bbc"               , crc_id_13_bbc               },
    { "crc-14-darc"              , crc_id_14_darc              },
    { "crc-14-gsm"               , crc_id_14_gsm               },
    { "crc-15"                   , crc_id_15_can               },
    { "crc-15-can"               , crc_id_15_can               },
    { "crc-15-mpt1327"           , crc_id_15_mpt1327           },
    { "crc-16"                   , crc_id_16_arc               },
    { "crc-16-acorn"             , crc_id_16_xmodem            },
    { "crc-16-arc"               , crc_id_16_arc               },
    { "crc-16-aug-ccitt"         , crc_id_16_spi_fujitsu       },
    { "crc-16-autosar"           , crc_id_16_ibm_3740          },
    { "crc-16-bluetooth"         , crc_id_16_kermit            },
    { "crc-16-buypass"           , crc_id_16_umts              },
    { "crc-16-ccitt"             , crc_id_16_kermit            },
    { "crc-16-ccitt-false"       , crc_id_16_ibm_3740          },
    { "crc-16-ccitt-true"        , crc_id_16_kermit            },
    { "crc-16-cdma2000"          , crc_id_16_cdma2000          },
    { "crc-16-cms"               , crc_id_16_cms               },
    { "crc-16-darc"              , crc_id_16_genibus           },
    { "crc-16-dds-110"           , crc_id_16_dds_110           },
    { "crc-16-dect-r"            , crc_id_16_dect_r            },
    { "crc-16-dect-x"            , crc_id_16_dect_x            },
    { "crc-16-dnp"               , crc_id_16_dnp               },
    { "crc-16-en-13757"          , crc_id_16_en_13757          },
    { "crc-16-epc"               , crc_id_16_genibus           },
    { "crc-16-epc-c1g2"          , crc_id_16_genibus           },
    { "crc-16-genibus"           , crc_id_16_genibus           },
    { "crc-16-gsm"               , crc_id_16_gsm               },
    { "crc-16-i-code"            , crc_id_16_genibus           },
    { "crc-16-ibm-3740"          , crc_id_16_ibm_3740          },
    { "crc-16-ibm-sdlc"          , crc_id_16_ibm_sdlc          },
    { "crc-16-iec-61158-2"       , crc_id_16_profibus          },
    { "crc-16-iso-hdlc"          , crc_id_16_ibm_sdlc          },
    { "crc-16-iso-iec-14443-3-a" , crc_id_16_iso_iec_14443_3_a },
    { "crc-16-iso-iec-14443-3-b" , crc_id_16_ibm_sdlc          },
    { "crc-16-kermit"            , crc_id_16_kermit            },
    { "crc-16-lha"               , crc_id_16_arc               },
    { "crc-16-lj1200"            , crc_id_16_lj1200            },
    { "crc-16-lte"               , crc_id_16_xmodem            },
    { "crc-16-m17"               , crc_id_16_m17               },
    { "crc-16-maxim"             , crc_id_16_maxim_dow         },
    { "crc-16-maxim-dow"         , crc_id_16_maxim_dow         },
    { "crc-16-mcrf4xx"           , crc_id_16_mcrf4xx           },
    { "crc-16-modbus"            , crc_id_16_modbus            },
    { "crc-16-nrsc-5"            , crc_id_16_nrsc_5            },
    { "crc-16-opensafety-a"      , crc_id_16_opensafety_a      },
    { "crc-16-opensafety-b"      , crc_id_16_opensafety_b      },
    { "crc-16-profibus"          , crc_id_16_profibus          },
    { "crc-16-riello"            , crc_id_16_riello            },
    { "crc-16-spi-fujitsu"       , crc_id_16_spi_fujitsu       },
    { "crc-16-t10-dif"           , crc_id_16_t10_dif           },
    { "crc-16-teledisk"          , crc_id_16_teledisk          },
    { "crc-16-tms37157"          , crc_id_16_tms37157          },
    { "crc-16-umts"              , crc_id_16_umts              },
    { "crc-16-usb"               , crc_id_16_usb               },
    { "crc-16-v-41-lsb"          , crc_id_16_kermit            },
    { "crc-16-v-41-msb"          , crc_id_16_xmodem            },
    { "crc-16-verifone"          , crc_id_16_umts              },
    { "crc-16-x-25"              , crc_id_16_ibm_sdlc          },
    { "crc-16-xmodem"            , crc_id_16_xmodem            },
    { "crc-17-can-fd"            , crc_id_17_can_fd            },
    { "crc-21-can-fd"            , crc_id_21_can_fd            },
    { "crc-24"                   , crc_id_24_openpgp           },
    { "crc-24-ble"               , crc_id_24_ble               },
    { "crc-24-flexray-a"         , crc_id_24_flexray_a         },
    { "crc-24-flexray-b"         , crc_id_24_flexray_b         },
    { "crc-24-interlaken"        , crc_id_24_interlaken        },
    { "crc-24-lte-a"             , crc_id_24_lte_a             },
    { "crc-24-lte-b"             , crc_id_24_lte_b             },
    { "crc-24-openpgp"           , crc_id_24_openpgp           },
    { "crc-24-os-9"              , crc_id_24_os_9              },
    { "crc-3-gsm"                , crc_id_3_gsm                },
    { "crc-3-rohc"               , crc_id_3_rohc               },
    { "crc-30-cdma"              , crc_id_30_cdma              },
    { "crc-31-philips"           , crc_id_31_philips           },
    { "crc-32"                   , crc_id_32_iso_hdlc          },
    { "crc-32-aal5"              , crc_id_32_bzip2             },
    { "crc-32-adccp"             , crc_id_32_iso_hdlc          },
    { "crc-32-aixm"              , crc_id_32_aixm              },
    { "crc-32-autosar"           , crc_id_32_autosar           },
    { "crc-32-base91-c"          , crc_id_32_iscsi             },
    { "crc-32-base91-d"          , crc_id_32_base91_d          },
    { "crc-32-bzip2"             , crc_id_32_bzip2             },
    { "crc-32-castagnoli"        , crc_id_32_iscsi             },
    { "crc-32-cd-rom-edc"        , crc_id_32_cd_rom_edc        },
    { "crc-32-cksum"             , crc_id_32_cksum             },
    { "crc-32-dect-b"            , crc_id_32_bzip2             },
    { "crc-32-interlaken"        , crc_id_32_iscsi             },
    { "crc-32-iscsi"             , crc_id_32_iscsi             },
    { "crc-32-iso-hdlc"          , crc_id_32_iso_hdlc          },
    { "crc-32-jamcrc"            , crc_id_32_jamcrc            },
    { "crc-32-mef"               , crc_id_32_mef               },
    { "crc-32-mpeg-2"            , crc_id_32_mpeg_2            },
    { "crc-32-nvme"              , crc_id_32_iscsi             },
    { "crc-32-posix"             , crc_id_32_cksum             },
    { "crc-32-v-42"              , crc_id_32_iso_hdlc          },
    { "crc-32-xfer"              , crc_id_32_xfer              },
    { "crc-32-xz"                , crc_id_32_iso_hdlc          },
    { "crc-32c"                  , crc_id_32_iscsi             },
    { "crc-32d"                  , crc_id_32_base91_d          },
    { "crc-32q"                  , crc_id_32_aixm              },
    { "crc-4-g-704"              , crc_id_4_g_704              },
    { "crc-4-interlaken"         , crc_id_4_interlaken         },
    { "crc-4-itu"                , crc_id_4_g_704              },
    { "crc-40-gsm"               , crc_id_40_gsm               },
    { "crc-5-epc"                , crc_id_5_epc_c1g2           },
    { "crc-5-epc-c1g2"           , crc_id_5_epc_c1g2           },
    { "crc-5-g-704"              , crc_id_5_g_704              },
    { "crc-5-itu"                , crc_id_5_g_704              },
    { "crc-5-usb"                , crc_id_5_usb                },
    { "crc-6-cdma2000-a"         , crc_id_6_cdma2000_a         },
    { "crc-6-cdma2000-b"         , crc_id_6_cdma2000_b         },
    { "crc-6-darc"               , crc_id_6_darc               },
    { "crc-6-g-704"              , crc_id_6_g_704              },
    { "crc-6-gsm"                , crc_id_6_gsm                },
    { "crc-6-itu"                , crc_id_6_g_704              },
    { "crc-64"                   , crc_id_64_ecma_182          },
    { "crc-64-ecma-182"          , crc_id_64_ecma_182          },
    { "crc-64-go-ecma"           , crc_id_64_xz                },
    { "crc-64-go-iso"            , crc_id_64_go_iso            },
    { "crc-64-ms"                , crc_id_64_ms                },
    { "crc-64-nvme"              , crc_id_64_nvme              },
    { "crc-64-redis"             , crc_id_64_redis             },
    { "crc-64-we"                , crc_id_64_we                },
    { "crc-64-xz"                , crc_id_64_xz                },
    { "crc-7"                    , crc_id_7_mmc                },
    { "crc-7-mmc"                , crc_id_7_mmc                },
    { "crc-7-rohc"               , crc_id_7_rohc               },
    { "crc-7-umts"               , crc_id_7_umts               },
    { "crc-8"                    , crc_id_8_smbus              },
    { "crc-8-aes"                , crc_id_8_tech_3250          },
    { "crc-8-autosar"            , crc_id_8_autosar            },
    { "crc-8-bluetooth"          , crc_id_8_bluetooth          },
    { "crc-8-cdma2000"           , crc_id_8_cdma2000           },
    { "crc-8-darc"               , crc_id_8_darc               },
    { "crc-8-dvb-s2"             , crc_id_8_dvb_s2             },
    { "crc-8-ebu"                , crc_id_8_tech_3250          },
    { "crc-8-gsm-a"              , crc_id_8_gsm_a              },
    { "crc-8-gsm-b"              , crc_id_8_gsm_b              },
    { "crc-8-hitag"              , crc_id_8_hitag              },
    { "crc-8-i-432-1"            , crc_id_8_i_432_1            },
    { "crc-8-i-code"             , crc_id_8_i_code             },
    { "crc-8-itu"                , crc_id_8_i_432_1            },
    { "crc-8-lte"                , crc_id_8_lte                },
    { "crc-8-maxim"              , crc_id_8_maxim_dow          },
    { "crc-8-maxim-dow"          , crc_id_8_maxim_dow          },
    { "crc-8-mifare-mad"         , crc_id_8_mifare_mad         },
    { "crc-8-nrsc-5"             , crc_id_8_nrsc_5             },
    { "crc-8-opensafety"         , crc_id_8_opensafety         },
    { "crc-8-rohc"               , crc_id_8_rohc               },
    { "crc-8-sae-j1850"          , crc_id_8_sae_j1850          },
    { "crc-8-smbus"              , crc_id_8_smbus              },
    { "crc-8-tech-3250"          , crc_id_8_tech_3250          },
    { "crc-8-wcdma"              , crc_id_8_wcdma              },
    { "crc-a"                    , crc_id_16_iso_iec_14443_3_a },
    { "crc-b"                    , crc_id_16_ibm_sdlc          },
    { "crc-ccitt"                , crc_id_16_kermit            },
    { "crc-ibm"                  , crc_id_16_arc               },
    { "dow-crc"                  , crc_id_8_maxim_dow          },
    { "jamcrc"                   , crc_id_32_jamcrc            },
    { "kermit"                   , crc_id_16_kermit            },
    { "modbus"                   , crc_id_16_modbus            },
    { "pkzip"                    , crc_id_32_iso_hdlc          },
    { "r-crc-16"                 , crc_id_16_dect_r            },
    { "x-25"                     , crc_id_16_ibm_sdlc          },
    { "x-crc-12"                 , crc_id_12_dect              },
    { "x-crc-16"                 , crc_id_16_dect_x            },
    { "xfer"                     , crc_id_32_xfer              },
    { "xmodem"                   , crc_id_16_xmodem            },
    { "zmodem"                   , crc_id_16_xmodem            },
    { NULL, crc_id_count }  /* sentinel */
};


/* CRC configuration descriptor */
typedef struct {
    crc_u64 poly;       /* polynomial */
    crc_u64 init;       /* initial value */
    crc_u64 xorout;     /* output XOR mask */
    crc_u8 width;       /* bit width */
    crc_u8 refin;       /* reflected input */
    crc_u8 refout;      /* reflected output */
} crc_config;


/*
  Configurations from:  https://reveng.sourceforge.io/crc-catalogue/
*/
static const crc_config crc_templates[crc_id_count] = {
/*                              poly                   init                   xorout                 wi ri ro */
/* crc_3_gsm                */{ 0x0000000000000003uLL, 0x0000000000000000uLL, 0x0000000000000007uLL,  3, 0, 0 },
/* crc_3_rohc               */{ 0x0000000000000003uLL, 0x0000000000000007uLL, 0x0000000000000000uLL,  3, 1, 1 },
/* crc_4_g_704              */{ 0x0000000000000003uLL, 0x0000000000000000uLL, 0x0000000000000000uLL,  4, 1, 1 },
/* crc_4_interlaken         */{ 0x0000000000000003uLL, 0x000000000000000FuLL, 0x000000000000000FuLL,  4, 0, 0 },
/* crc_5_epc_c1g2           */{ 0x0000000000000009uLL, 0x0000000000000009uLL, 0x0000000000000000uLL,  5, 0, 0 },
/* crc_5_g_704              */{ 0x0000000000000015uLL, 0x0000000000000000uLL, 0x0000000000000000uLL,  5, 1, 1 },
/* crc_5_usb                */{ 0x0000000000000005uLL, 0x000000000000001FuLL, 0x000000000000001FuLL,  5, 1, 1 },
/* crc_6_cdma2000_a         */{ 0x0000000000000027uLL, 0x000000000000003FuLL, 0x0000000000000000uLL,  6, 0, 0 },
/* crc_6_cdma2000_b         */{ 0x0000000000000007uLL, 0x000000000000003FuLL, 0x0000000000000000uLL,  6, 0, 0 },
/* crc_6_darc               */{ 0x0000000000000019uLL, 0x0000000000000000uLL, 0x0000000000000000uLL,  6, 1, 1 },
/* crc_6_g_704              */{ 0x0000000000000003uLL, 0x0000000000000000uLL, 0x0000000000000000uLL,  6, 1, 1 },
/* crc_6_gsm                */{ 0x000000000000002FuLL, 0x0000000000000000uLL, 0x000000000000003FuLL,  6, 0, 0 },
/* crc_7_mmc                */{ 0x0000000000000009uLL, 0x0000000000000000uLL, 0x0000000000000000uLL,  7, 0, 0 },
/* crc_7_rohc               */{ 0x000000000000004FuLL, 0x000000000000007FuLL, 0x0000000000000000uLL,  7, 1, 1 },
/* crc_7_umts               */{ 0x0000000000000045uLL, 0x0000000000000000uLL, 0x0000000000000000uLL,  7, 0, 0 },
/* crc_8_autosar            */{ 0x000000000000002FuLL, 0x00000000000000FFuLL, 0x00000000000000FFuLL,  8, 0, 0 },
/* crc_8_bluetooth          */{ 0x00000000000000A7uLL, 0x0000000000000000uLL, 0x0000000000000000uLL,  8, 1, 1 },
/* crc_8_cdma2000           */{ 0x000000000000009BuLL, 0x00000000000000FFuLL, 0x0000000000000000uLL,  8, 0, 0 },
/* crc_8_darc               */{ 0x0000000000000039uLL, 0x0000000000000000uLL, 0x0000000000000000uLL,  8, 1, 1 },
/* crc_8_dvb_s2             */{ 0x00000000000000D5uLL, 0x0000000000000000uLL, 0x0000000000000000uLL,  8, 0, 0 },
/* crc_8_gsm_a              */{ 0x000000000000001DuLL, 0x0000000000000000uLL, 0x0000000000000000uLL,  8, 0, 0 },
/* crc_8_gsm_b              */{ 0x0000000000000049uLL, 0x0000000000000000uLL, 0x00000000000000FFuLL,  8, 0, 0 },
/* crc_8_hitag              */{ 0x000000000000001DuLL, 0x00000000000000FFuLL, 0x0000000000000000uLL,  8, 0, 0 },
/* crc_8_i_432_1            */{ 0x0000000000000007uLL, 0x0000000000000000uLL, 0x0000000000000055uLL,  8, 0, 0 },
/* crc_8_i_code             */{ 0x000000000000001DuLL, 0x00000000000000FDuLL, 0x0000000000000000uLL,  8, 0, 0 },
/* crc_8_lte                */{ 0x000000000000009BuLL, 0x0000000000000000uLL, 0x0000000000000000uLL,  8, 0, 0 },
/* crc_8_maxim_dow          */{ 0x0000000000000031uLL, 0x0000000000000000uLL, 0x0000000000000000uLL,  8, 1, 1 },
/* crc_8_mifare_mad         */{ 0x000000000000001DuLL, 0x00000000000000C7uLL, 0x0000000000000000uLL,  8, 0, 0 },
/* crc_8_nrsc_5             */{ 0x0000000000000031uLL, 0x00000000000000FFuLL, 0x0000000000000000uLL,  8, 0, 0 },
/* crc_8_opensafety         */{ 0x000000000000002FuLL, 0x0000000000000000uLL, 0x0000000000000000uLL,  8, 0, 0 },
/* crc_8_rohc               */{ 0x0000000000000007uLL, 0x00000000000000FFuLL, 0x0000000000000000uLL,  8, 1, 1 },
/* crc_8_sae_j1850          */{ 0x000000000000001DuLL, 0x00000000000000FFuLL, 0x00000000000000FFuLL,  8, 0, 0 },
/* crc_8_smbus              */{ 0x0000000000000007uLL, 0x0000000000000000uLL, 0x0000000000000000uLL,  8, 0, 0 },
/* crc_8_tech_3250          */{ 0x000000000000001DuLL, 0x00000000000000FFuLL, 0x0000000000000000uLL,  8, 1, 1 },
/* crc_8_wcdma              */{ 0x000000000000009BuLL, 0x0000000000000000uLL, 0x0000000000000000uLL,  8, 1, 1 },
/* crc_10_atm               */{ 0x0000000000000233uLL, 0x0000000000000000uLL, 0x0000000000000000uLL, 10, 0, 0 },
/* crc_10_cdma2000          */{ 0x00000000000003D9uLL, 0x00000000000003FFuLL, 0x0000000000000000uLL, 10, 0, 0 },
/* crc_10_gsm               */{ 0x0000000000000175uLL, 0x0000000000000000uLL, 0x00000000000003FFuLL, 10, 0, 0 },
/* crc_11_flexray           */{ 0x0000000000000385uLL, 0x000000000000001AuLL, 0x0000000000000000uLL, 11, 0, 0 },
/* crc_11_umts              */{ 0x0000000000000307uLL, 0x0000000000000000uLL, 0x0000000000000000uLL, 11, 0, 0 },
/* crc_12_cdma2000          */{ 0x0000000000000F13uLL, 0x0000000000000FFFuLL, 0x0000000000000000uLL, 12, 0, 0 },
/* crc_12_dect              */{ 0x000000000000080FuLL, 0x0000000000000000uLL, 0x0000000000000000uLL, 12, 0, 0 },
/* crc_12_gsm               */{ 0x0000000000000D31uLL, 0x0000000000000000uLL, 0x0000000000000FFFuLL, 12, 0, 0 },
/* crc_12_umts              */{ 0x000000000000080FuLL, 0x0000000000000000uLL, 0x0000000000000000uLL, 12, 0, 1 },
/* crc_13_bbc               */{ 0x0000000000001CF5uLL, 0x0000000000000000uLL, 0x0000000000000000uLL, 13, 0, 0 },
/* crc_14_darc              */{ 0x0000000000000805uLL, 0x0000000000000000uLL, 0x0000000000000000uLL, 14, 1, 1 },
/* crc_14_gsm               */{ 0x000000000000202DuLL, 0x0000000000000000uLL, 0x0000000000003FFFuLL, 14, 0, 0 },
/* crc_15_can               */{ 0x0000000000004599uLL, 0x0000000000000000uLL, 0x0000000000000000uLL, 15, 0, 0 },
/* crc_15_mpt1327           */{ 0x0000000000006815uLL, 0x0000000000000000uLL, 0x0000000000000001uLL, 15, 0, 0 },
/* crc_16_arc               */{ 0x0000000000008005uLL, 0x0000000000000000uLL, 0x0000000000000000uLL, 16, 1, 1 },
/* crc_16_cdma2000          */{ 0x000000000000C867uLL, 0x000000000000FFFFuLL, 0x0000000000000000uLL, 16, 0, 0 },
/* crc_16_cms               */{ 0x0000000000008005uLL, 0x000000000000FFFFuLL, 0x0000000000000000uLL, 16, 0, 0 },
/* crc_16_dds_110           */{ 0x0000000000008005uLL, 0x000000000000800DuLL, 0x0000000000000000uLL, 16, 0, 0 },
/* crc_16_dect_r            */{ 0x0000000000000589uLL, 0x0000000000000000uLL, 0x0000000000000001uLL, 16, 0, 0 },
/* crc_16_dect_x            */{ 0x0000000000000589uLL, 0x0000000000000000uLL, 0x0000000000000000uLL, 16, 0, 0 },
/* crc_16_dnp               */{ 0x0000000000003D65uLL, 0x0000000000000000uLL, 0x000000000000FFFFuLL, 16, 1, 1 },
/* crc_16_en_13757          */{ 0x0000000000003D65uLL, 0x0000000000000000uLL, 0x000000000000FFFFuLL, 16, 0, 0 },
/* crc_16_genibus           */{ 0x0000000000001021uLL, 0x000000000000FFFFuLL, 0x000000000000FFFFuLL, 16, 0, 0 },
/* crc_16_gsm               */{ 0x0000000000001021uLL, 0x0000000000000000uLL, 0x000000000000FFFFuLL, 16, 0, 0 },
/* crc_16_ibm_3740          */{ 0x0000000000001021uLL, 0x000000000000FFFFuLL, 0x0000000000000000uLL, 16, 0, 0 },
/* crc_16_ibm_sdlc          */{ 0x0000000000001021uLL, 0x000000000000FFFFuLL, 0x000000000000FFFFuLL, 16, 1, 1 },
/* crc_16_iso_iec_14443_3_a */{ 0x0000000000001021uLL, 0x000000000000C6C6uLL, 0x0000000000000000uLL, 16, 1, 1 },
/* crc_16_kermit            */{ 0x0000000000001021uLL, 0x0000000000000000uLL, 0x0000000000000000uLL, 16, 1, 1 },
/* crc_16_lj1200            */{ 0x0000000000006F63uLL, 0x0000000000000000uLL, 0x0000000000000000uLL, 16, 0, 0 },
/* crc_16_m17               */{ 0x0000000000005935uLL, 0x000000000000FFFFuLL, 0x0000000000000000uLL, 16, 0, 0 },
/* crc_16_maxim_dow         */{ 0x0000000000008005uLL, 0x0000000000000000uLL, 0x000000000000FFFFuLL, 16, 1, 1 },
/* crc_16_mcrf4xx           */{ 0x0000000000001021uLL, 0x000000000000FFFFuLL, 0x0000000000000000uLL, 16, 1, 1 },
/* crc_16_modbus            */{ 0x0000000000008005uLL, 0x000000000000FFFFuLL, 0x0000000000000000uLL, 16, 1, 1 },
/* crc_16_nrsc_5            */{ 0x000000000000080BuLL, 0x000000000000FFFFuLL, 0x0000000000000000uLL, 16, 1, 1 },
/* crc_16_opensafety_a      */{ 0x0000000000005935uLL, 0x0000000000000000uLL, 0x0000000000000000uLL, 16, 0, 0 },
/* crc_16_opensafety_b      */{ 0x000000000000755BuLL, 0x0000000000000000uLL, 0x0000000000000000uLL, 16, 0, 0 },
/* crc_16_profibus          */{ 0x0000000000001DCFuLL, 0x000000000000FFFFuLL, 0x000000000000FFFFuLL, 16, 0, 0 },
/* crc_16_riello            */{ 0x0000000000001021uLL, 0x000000000000B2AAuLL, 0x0000000000000000uLL, 16, 1, 1 },
/* crc_16_spi_fujitsu       */{ 0x0000000000001021uLL, 0x0000000000001D0FuLL, 0x0000000000000000uLL, 16, 0, 0 },
/* crc_16_t10_dif           */{ 0x0000000000008BB7uLL, 0x0000000000000000uLL, 0x0000000000000000uLL, 16, 0, 0 },
/* crc_16_teledisk          */{ 0x000000000000A097uLL, 0x0000000000000000uLL, 0x0000000000000000uLL, 16, 0, 0 },
/* crc_16_tms37157          */{ 0x0000000000001021uLL, 0x00000000000089ECuLL, 0x0000000000000000uLL, 16, 1, 1 },
/* crc_16_umts              */{ 0x0000000000008005uLL, 0x0000000000000000uLL, 0x0000000000000000uLL, 16, 0, 0 },
/* crc_16_usb               */{ 0x0000000000008005uLL, 0x000000000000FFFFuLL, 0x000000000000FFFFuLL, 16, 1, 1 },
/* crc_16_xmodem            */{ 0x0000000000001021uLL, 0x0000000000000000uLL, 0x0000000000000000uLL, 16, 0, 0 },
/* crc_17_can_fd            */{ 0x000000000001685BuLL, 0x0000000000000000uLL, 0x0000000000000000uLL, 17, 0, 0 },
/* crc_21_can_fd            */{ 0x0000000000102899uLL, 0x0000000000000000uLL, 0x0000000000000000uLL, 21, 0, 0 },
/* crc_24_ble               */{ 0x000000000000065BuLL, 0x0000000000555555uLL, 0x0000000000000000uLL, 24, 1, 1 },
/* crc_24_flexray_a         */{ 0x00000000005D6DCBuLL, 0x0000000000FEDCBAuLL, 0x0000000000000000uLL, 24, 0, 0 },
/* crc_24_flexray_b         */{ 0x00000000005D6DCBuLL, 0x0000000000ABCDEFuLL, 0x0000000000000000uLL, 24, 0, 0 },
/* crc_24_interlaken        */{ 0x0000000000328B63uLL, 0x0000000000FFFFFFuLL, 0x0000000000FFFFFFuLL, 24, 0, 0 },
/* crc_24_lte_a             */{ 0x0000000000864CFBuLL, 0x0000000000000000uLL, 0x0000000000000000uLL, 24, 0, 0 },
/* crc_24_lte_b             */{ 0x0000000000800063uLL, 0x0000000000000000uLL, 0x0000000000000000uLL, 24, 0, 0 },
/* crc_24_openpgp           */{ 0x0000000000864CFBuLL, 0x0000000000B704CEuLL, 0x0000000000000000uLL, 24, 0, 0 },
/* crc_24_os_9              */{ 0x0000000000800063uLL, 0x0000000000FFFFFFuLL, 0x0000000000FFFFFFuLL, 24, 0, 0 },
/* crc_30_cdma              */{ 0x000000002030B9C7uLL, 0x000000003FFFFFFFuLL, 0x000000003FFFFFFFuLL, 30, 0, 0 },
/* crc_31_philips           */{ 0x0000000004C11DB7uLL, 0x000000007FFFFFFFuLL, 0x000000007FFFFFFFuLL, 31, 0, 0 },
/* crc_32_aixm              */{ 0x00000000814141ABuLL, 0x0000000000000000uLL, 0x0000000000000000uLL, 32, 0, 0 },
/* crc_32_autosar           */{ 0x00000000F4ACFB13uLL, 0x00000000FFFFFFFFuLL, 0x00000000FFFFFFFFuLL, 32, 1, 1 },
/* crc_32_base91_d          */{ 0x00000000A833982BuLL, 0x00000000FFFFFFFFuLL, 0x00000000FFFFFFFFuLL, 32, 1, 1 },
/* crc_32_bzip2             */{ 0x0000000004C11DB7uLL, 0x00000000FFFFFFFFuLL, 0x00000000FFFFFFFFuLL, 32, 0, 0 },
/* crc_32_cd_rom_edc        */{ 0x000000008001801BuLL, 0x0000000000000000uLL, 0x0000000000000000uLL, 32, 1, 1 },
/* crc_32_cksum             */{ 0x0000000004C11DB7uLL, 0x0000000000000000uLL, 0x00000000FFFFFFFFuLL, 32, 0, 0 },
/* crc_32_iscsi             */{ 0x000000001EDC6F41uLL, 0x00000000FFFFFFFFuLL, 0x00000000FFFFFFFFuLL, 32, 1, 1 },
/* crc_32_iso_hdlc          */{ 0x0000000004C11DB7uLL, 0x00000000FFFFFFFFuLL, 0x00000000FFFFFFFFuLL, 32, 1, 1 },
/* crc_32_jamcrc            */{ 0x0000000004C11DB7uLL, 0x00000000FFFFFFFFuLL, 0x0000000000000000uLL, 32, 1, 1 },
/* crc_32_mef               */{ 0x00000000741B8CD7uLL, 0x00000000FFFFFFFFuLL, 0x0000000000000000uLL, 32, 1, 1 },
/* crc_32_mpeg_2            */{ 0x0000000004C11DB7uLL, 0x00000000FFFFFFFFuLL, 0x0000000000000000uLL, 32, 0, 0 },
/* crc_32_xfer              */{ 0x00000000000000AFuLL, 0x0000000000000000uLL, 0x0000000000000000uLL, 32, 0, 0 },
/* crc_40_gsm               */{ 0x0000000004820009uLL, 0x0000000000000000uLL, 0x000000FFFFFFFFFFuLL, 40, 0, 0 },
/* crc_64_ecma_182          */{ 0x42F0E1EBA9EA3693uLL, 0x0000000000000000uLL, 0x0000000000000000uLL, 64, 0, 0 },
/* crc_64_go_iso            */{ 0x000000000000001BuLL, 0xFFFFFFFFFFFFFFFFuLL, 0xFFFFFFFFFFFFFFFFuLL, 64, 1, 1 },
/* crc_64_ms                */{ 0x259C84CBA6426349uLL, 0xFFFFFFFFFFFFFFFFuLL, 0x0000000000000000uLL, 64, 1, 1 },
/* crc_64_nvme              */{ 0xAD93D23594C93659uLL, 0xFFFFFFFFFFFFFFFFuLL, 0xFFFFFFFFFFFFFFFFuLL, 64, 1, 1 },
/* crc_64_redis             */{ 0xAD93D23594C935A9uLL, 0x0000000000000000uLL, 0x0000000000000000uLL, 64, 1, 1 },
/* crc_64_we                */{ 0x42F0E1EBA9EA3693uLL, 0xFFFFFFFFFFFFFFFFuLL, 0xFFFFFFFFFFFFFFFFuLL, 64, 0, 0 },
/* crc_64_xz                */{ 0x42F0E1EBA9EA3693uLL, 0xFFFFFFFFFFFFFFFFuLL, 0xFFFFFFFFFFFFFFFFuLL, 64, 1, 1 }
};


/* Finds the template ID mapped by the given name */
static crc_id
crc_find_id(const char *name)
{
    /* Binary search (names sorted by ASCII order) */
    assert(name);
    size_t namelen = strlen(name);
    size_t itemcount = sizeof(crc_name_ids) / sizeof(crc_name_id);
    size_t right = itemcount - 1;  /* skip sentinel */
    size_t left = 0;

    while (left <= right) {
        size_t middle = left + ((right - left) >> 1);
        const char *itemname = crc_name_ids[middle].name;
        assert(itemname);
        size_t itemlen = strlen(itemname);
        size_t minlen = (namelen < itemlen) ? namelen : itemlen;
        int cmp = memcmp(name, itemname, minlen + 1);

        if (cmp < 0) {
            right = middle - 1;
        }
        else if (cmp > 0) {
            left = middle + 1;
        }
        else {
            return crc_name_ids[middle].id;
        }
    }
    return crc_id_count;  /* invalid */
}


/* Finds the template configuration mapped by the given name */
static const crc_config *
crc_find_config(const char *name)
{
    crc_id id = crc_find_id(name);
    if (id < crc_id_count) {
        return &crc_templates[id];
    }
    return NULL;
}


/* Returns the Python dictionary with the summary of all the templates */
static PyObject *
crc_templates_dict(void)
{
    PyObject *key = NULL;
    PyObject *tuple = NULL;
    PyObject *item = NULL;
    PyObject *dict = PyDict_New();
    CHECK(dict);

    for (const crc_name_id *couple = crc_name_ids; couple->name; ++couple) {
        const crc_config *config = &crc_templates[couple->id];
        CHECK(key = PyUnicode_FromString(couple->name));
        CHECK(tuple = PyTuple_New(6));

        CHECK(item = PyLong_FromUnsignedLong(config->width));
        PyTuple_SET_ITEM(tuple, 0, item);

        CHECK(item = PyLong_FromUnsignedLongLong(config->poly));
        PyTuple_SET_ITEM(tuple, 1, item);

        CHECK(item = PyLong_FromUnsignedLongLong(config->init));
        PyTuple_SET_ITEM(tuple, 2, item);

        CHECK(item = PyBool_FromLong((long)config->refin));
        PyTuple_SET_ITEM(tuple, 3, item);

        CHECK(item = PyBool_FromLong((long)config->refout));
        PyTuple_SET_ITEM(tuple, 4, item);

        CHECK(item = PyLong_FromUnsignedLongLong(config->xorout));
        PyTuple_SET_ITEM(tuple, 5, item);

        CHECK(!PyDict_SetItem(dict, key, tuple));
        Py_CLEAR(key);
        Py_CLEAR(tuple);
        item = NULL;
    }
    goto finally;
error:
    Py_CLEAR(dict);
finally:
    Py_XDECREF(key);
    Py_XDECREF(tuple);
    Py_XDECREF(item);
    return dict;
}


/* ================================================================ */

struct crcu64_impl;  /* forward declaration */

/* Update function prototype */
typedef void (*crcu64_func_update)(struct crcu64_impl *impl,
                                   const crc_u8 *data,
                                   size_t size);

/* Implementation of a CRC algorithm */
typedef struct crcu64_impl {
    crc_u64 init;               /* optimized initial value */
    crc_u64 poly;               /* optimized polynomial */
    crc_u64 accum;              /* optimized current accumulator */
    crc_u64 xorout;             /* optimized output XOR mask */
    crc_u64 result;             /* cached digest result */
    crcu64_func_update update;  /* optimized update function */
    crc_u64 *bytewise;          /* optimized bytewise table, or NULL */
    crc_u64 *wordwise;          /* optimized wordwise table, or NULL */
    crc_u8 width;               /* bit width */
    crc_u8 refin;               /* reflected input */
    crc_u8 refout;              /* reflected output */
    crc_u8 dirty;               /* internal state changed */
} crcu64_impl;


/* Implementation constructor (requires further configuration!) */
static void
crcu64_impl_ctor(crcu64_impl *impl)
{
    assert(impl);
    impl->init     = 0;
    impl->poly     = 0;
    impl->accum    = 0;
    impl->xorout   = 0;
    impl->result   = 0;
    impl->update   = NULL;
    impl->bytewise = NULL;
    impl->wordwise = NULL;
    impl->width    = 0;
    impl->refin    = 0;
    impl->refout   = 0;
    impl->dirty    = 0;
}


/* Copies an implementation instance status to another instance */
static void
crcu64_impl_copy(crcu64_impl *dst, crcu64_impl *src)
{
    assert(dst);
    assert(src);
    dst->init     = src->init;
    dst->poly     = src->poly;
    dst->accum    = src->accum;
    dst->result   = src->result;
    dst->xorout   = src->xorout;
    dst->update   = src->update;
    dst->bytewise = src->bytewise;
    dst->wordwise = src->wordwise;
    dst->width    = src->width;
    dst->refin    = src->refin;
    dst->refout   = src->refout;
    dst->dirty    = src->dirty;
}


static inline crc_u64
crcu64_impl_internalize(const crcu64_impl *impl, crc_u64 value)
{
    assert(value <= crc_u64_bitmask(impl->width));
    if (impl->refin) {
        value = crc_u64_bitswap(value, impl->width);  /* precalc */
    } else {
        value <<= CRC_U64_LEAST - impl->width;  /* precalc */
    }
    return value;
}


static inline crc_u64
crcu64_impl_externalize(const crcu64_impl *impl, crc_u64 value)
{
    if (impl->refin) {
        value = crc_u64_bitswap(value, impl->width);  /* undo */
    } else {
        value >>= CRC_U64_LEAST - impl->width;  /* undo */
    }
    return value;
}


/* Resets the implementation to its configured initial state */
static void
crcu64_impl_clear_default(crcu64_impl *impl)
{
    assert(impl);
    impl->dirty = 0;
    impl->accum = impl->init;
    impl->result = crcu64_impl_externalize(impl, impl->init);
}


/* Resets the implementation to the provided initial state */
static void
crcu64_impl_clear_init(crcu64_impl *impl, crc_u64 init)
{
    assert(impl);
    assert(init <= crc_u64_bitmask(impl->width));
    impl->dirty = 0;
    impl->result = init;
    impl->accum = crcu64_impl_internalize(impl, init);
}


/* Updates the internal state with an input word and its bit width

  It updates the accumulator bit-by-bit (slowest)
*/
static void
crcu64_impl_update_word(crcu64_impl *impl, crc_u64 word, crc_u8 width)
{
    assert(impl);
    assert(width <= CRC_MAX_WIDTH);
    if (!width) {
        return;
    }
    crc_u64 poly  = impl->poly;
    crc_u64 accum = impl->accum;

    if (impl->refin) {
        accum ^= word;

        while (width--) {
            if (accum & 1) {
                accum = (accum >> 1) ^ poly;
            } else {
                accum = (accum >> 1);
            }
        }
    }
    else {
        accum ^= word << (CRC_U64_LEAST - width);

        while (width--) {
            if (accum & CRC_U64_TOP) {
                accum = (accum << 1) ^ poly;
            } else {
                accum = (accum << 1);
            }
        }
    }

    impl->accum = accum;
    impl->dirty = 1;
}


/* Updates the internal state with an input byte string

  It updates the accumulator bit-by-bit (slow)
*/
static void
crcu64_impl_update_bitwise(crcu64_impl *impl,
                           const crc_u8 *data,
                           size_t size)
{
    assert(impl);
    assert(!size || data);
    if (!size) {
        return;
    }
    assert((uintptr_t)data <= ((SIZE_MAX - size) + 1));
    const crc_u8 *end = &data[size];
    crc_u64 poly = impl->poly;
    crc_u64 accum = impl->accum;

    if (impl->refin) {
        while (data != end) {
            crc_u64 byte = *data++;
            accum ^= byte;

            for (crc_u16 bit = 0; bit < CRC_U8_WIDTH; ++bit) {
                if (accum & 1) {
                    accum = (accum >> 1) ^ poly;
                } else {
                    accum = (accum >> 1);
                }
            }
        }
    }
    else {
        while (data != end) {
            crc_u64 byte = *data++;
            accum ^= byte << (CRC_U64_LEAST - CRC_U8_WIDTH);

            for (crc_u16 bit = 0; bit < CRC_U8_WIDTH; ++bit) {
                if (accum & CRC_U64_TOP) {
                    accum = (accum << 1) ^ poly;
                } else {
                    accum = (accum << 1);
                }
            }
        }
    }

    impl->accum = accum;
    impl->dirty = 1;
}


/* Updates the internal state with an input byte string, via byte table

  It updates the accumulator with a single-byte lookup table (fast)
*/
static void
crcu64_impl_update_bytewise(crcu64_impl *impl,
                            const crc_u8 *data,
                            size_t size)
{
    assert(impl);
    assert(impl->bytewise);
    assert(!size || data);
    if (!size) {
        return;
    }
    assert((uintptr_t)data <= ((SIZE_MAX - size) + 1));
    const crc_u8 *end = &data[size];
    const crc_u64 *table = impl->bytewise;
    crc_u64 accum = impl->accum;

    if (impl->refin) {
        while (data != end) {
            crc_u64 byte = *data++;
            crc_u64 upper = accum >> CRC_U8_WIDTH;
            crc_u64 lower = accum;
            lower = table[(byte ^ lower) & CRC_U8_MASK];
            accum = lower ^ upper;
        }
    }
    else {
        while (data != end) {
            crc_u64 byte = *data++;
            crc_u64 lower = accum << CRC_U8_WIDTH;
            crc_u64 upper = accum >> (CRC_U64_LEAST - CRC_U8_WIDTH);
            upper = table[(byte ^ upper) & CRC_U8_MASK];
            accum = lower ^ upper;
        }
    }

    impl->accum = accum;
    impl->dirty = 1;
}


/* Snippet for a wordwise update stage, little-endian data */
static crc_u64
crcu64_wordwise_little(const crc_u64 *table, crc_u64 accum)
{
#if ((CRC_U8_WIDTH == 8) && (CRC_MAX_WIDTH == 64))
    accum = (table[(7 * CRC_U8_COUNT) + ((accum >>  0) & CRC_U8_MASK)] ^
             table[(6 * CRC_U8_COUNT) + ((accum >>  8) & CRC_U8_MASK)] ^
             table[(5 * CRC_U8_COUNT) + ((accum >> 16) & CRC_U8_MASK)] ^
             table[(4 * CRC_U8_COUNT) + ((accum >> 24) & CRC_U8_MASK)] ^
             table[(3 * CRC_U8_COUNT) + ((accum >> 32) & CRC_U8_MASK)] ^
             table[(2 * CRC_U8_COUNT) + ((accum >> 40) & CRC_U8_MASK)] ^
             table[(1 * CRC_U8_COUNT) + ((accum >> 48) & CRC_U8_MASK)] ^
             table[(0 * CRC_U8_COUNT) + ((accum >> 56) & CRC_U8_MASK)]);
#else
    crc_u64 accum_ = 0;
    for (crc_u32 i = CRC_MAX_SIZE; i--; /**/) {
        accum_ ^= table[(i * CRC_U8_COUNT) + (accum & CRC_U8_MASK)];
        accum >>= CRC_U8_WIDTH;
    }
    accum = accum_;
#endif
    return accum;
}


/* Snippet for a wordwise update stage, big-endian data */
static crc_u64
crcu64_wordwise_big(const crc_u64 *table, crc_u64 accum)
{
#if ((CRC_U8_WIDTH == 8) && (CRC_MAX_WIDTH == 64))
    accum = (table[(0 * CRC_U8_COUNT) + ((accum >>  0) & CRC_U8_MASK)] ^
             table[(1 * CRC_U8_COUNT) + ((accum >>  8) & CRC_U8_MASK)] ^
             table[(2 * CRC_U8_COUNT) + ((accum >> 16) & CRC_U8_MASK)] ^
             table[(3 * CRC_U8_COUNT) + ((accum >> 24) & CRC_U8_MASK)] ^
             table[(4 * CRC_U8_COUNT) + ((accum >> 32) & CRC_U8_MASK)] ^
             table[(5 * CRC_U8_COUNT) + ((accum >> 40) & CRC_U8_MASK)] ^
             table[(6 * CRC_U8_COUNT) + ((accum >> 48) & CRC_U8_MASK)] ^
             table[(7 * CRC_U8_COUNT) + ((accum >> 56) & CRC_U8_MASK)]);
#else
    crc_u64 accum_ = 0;
    for (crc_u32 i = 0; i < CRC_MAX_SIZE; ++i) {
        accum_ ^= table[(i * CRC_U8_COUNT) + (accum & CRC_U8_MASK)];
        accum >>= CRC_U8_WIDTH;
    }
    accum = accum_;
#endif
    return accum;
}


/* Updates the internal state with an input byte string, via byte table

  It updates the accumulator with a multi-byte lookup table (fastest)
*/
static void
crcu64_impl_update_wordwise(crcu64_impl *impl,
                            const crc_u8 *data,
                            size_t size)
{
    assert(impl);
    assert(impl->wordwise);
    assert(!size || data);
    if (!size) {
        return;
    }
    assert((uintptr_t)data <= ((SIZE_MAX - size) + 1));

    size_t offset = (size_t)(uintptr_t)data % CRC_MAX_SIZE;
    if (offset) {
        offset = CRC_MAX_SIZE - offset;
        if (offset > size) {
            offset = size;
        }
        crcu64_impl_update_bytewise(impl, data, offset);
        data += offset;
        size -= offset;
    }

    if (size >= CRC_MAX_SIZE) {
        crc_u64 accum = impl->accum;

        if (is_little_endian()) {
            if (!impl->refin) {
                accum = crc_u64_byteswap(accum);
            }
            do {
                crc_u64 word = *(const crc_u64 *)data;
                accum ^= word;
                accum = crcu64_wordwise_little(impl->wordwise, accum);
                data += CRC_MAX_SIZE;
                size -= CRC_MAX_SIZE;
            } while (size >= CRC_MAX_SIZE);

            if (!impl->refin) {
                accum = crc_u64_byteswap(accum);
            }
        }
        else {
            if (impl->refin) {
                accum = crc_u64_byteswap(accum);
            }
            do {
                crc_u64 word = *(const crc_u64 *)data;
                accum ^= word;
                accum = crcu64_wordwise_big(impl->wordwise, accum);
                data += CRC_MAX_SIZE;
                size -= CRC_MAX_SIZE;
            } while (size >= CRC_MAX_SIZE);

            if (impl->refin) {
                accum = crc_u64_byteswap(accum);
            }
        }

        impl->accum = accum;
        impl->dirty = 1;
    }

    if (size) {
        crcu64_impl_update_bytewise(impl, data, size);
    }
}


/* Updates the instance with the configured optimized update method */
static inline void
crcu64_impl_update(crcu64_impl *impl, const crc_u8 *data, size_t size)
{
    assert(impl);
    assert(impl->update);
    impl->update(impl, data, size);
}


/* Feeds the input with a number of NULL bytes */
static void
crcu64_impl_zero_bytes(crcu64_impl *impl, size_t numbytes)
{
    assert(impl);
    if (!numbytes) {
        return;
    }
    /* There are much faster algorithms! */
    static const crc_u8 zerobuf[CRC_U8_COUNT] = {0};
    crcu64_func_update update = impl->update;
    assert(update);
    while (numbytes >= CRC_U8_COUNT) {
        numbytes -= CRC_U8_COUNT;
        update(impl, zerobuf, CRC_U8_COUNT);
    }
    if (numbytes) {
        update(impl, zerobuf, numbytes);
    }
}


/* Feeds the input with a number of NULL bits */
static void
crcu64_impl_zero_bits(crcu64_impl *impl, size_t numbits)
{
    assert(impl);
    size_t numbytes = numbits / CRC_U8_WIDTH;
    numbits -= numbytes * CRC_U8_WIDTH;
    crcu64_impl_zero_bytes(impl, numbytes);
    crcu64_impl_update_word(impl, 0, numbits);
}


/* Updates and returns the digest result value */
static crc_u64
crcu64_impl_digest(crcu64_impl *impl)
{
    assert(impl);

    if (impl->dirty) {
        impl->dirty = 0;
        crc_u8 width = impl->width;
        crc_u64 accum = impl->accum;

        if (!impl->refin) {
            accum >>= CRC_U64_LEAST - width;  /* undo */
        }

        if (impl->refin == impl->refout) {
            accum &= crc_u64_bitmask(width);
        } else {
            accum = crc_u64_bitswap(accum, width);
        }
        impl->result = accum ^ impl->xorout;
    }
    return impl->result;
}


/* Applies the nominal configuration, optimizing internally */
static const char *
crcu64_impl_configure(crcu64_impl *impl, const crc_config *config)
{
    assert(impl);
    assert(config);

    crc_u8 width = config->width;
    if ((width > CRC_MAX_WIDTH) || !width) {
        return "width out of range";
    }
    crc_u64 mask = crc_u64_bitmask(width);
    crc_u64 poly = config->poly;
    if ((poly > mask) || !poly) {
        return "poly out of range";
    }
    crc_u64 init = config->init;
    if (init > mask) {
        return "init out of range";
    }
    crc_u64 xorout = config->xorout;
    if (xorout > mask) {
        return "xorout out of range";
    }

    impl->width    = config->width;
    impl->refin    = config->refin;
    impl->refout   = config->refout;
    impl->init     = crcu64_impl_internalize(impl, init);
    impl->poly     = crcu64_impl_internalize(impl, poly);
    impl->accum    = impl->init;
    impl->xorout   = xorout;
    impl->result   = config->init;
    impl->update   = crcu64_impl_update_bitwise;
    impl->bytewise = NULL;
    impl->wordwise = NULL;

    return NULL;
}


/* Tabulates the optimized bytewise values for a given implementation */
static void
crcu64_impl_tabulate_bytewise(crcu64_impl *impl)
{
    assert(impl);
    assert(impl->bytewise);
    crc_u64 dirty_ = impl->dirty;  /* backup */
    crc_u64 accum_ = impl->accum;  /* backup */
    crc_u64 *table = impl->bytewise;

    for (crc_u16 byte = 0; byte < CRC_U8_COUNT; ++byte) {
        impl->accum = 0;
        crcu64_impl_update_word(impl, byte, CRC_U8_WIDTH);
        table[byte] = impl->accum;
    }

    impl->accum = accum_;  /* dirty */
    impl->dirty = dirty_;  /* dirty */
}


/* Tabulates the optimized wordwise values for a given implementation */
static void
crcu64_impl_tabulate_wordwise(crcu64_impl *impl)
{
    assert(impl);
    assert(impl->bytewise);
    assert(impl->wordwise);
    crc_u64 *table = impl->wordwise;
    crc_u8 byteswap = is_little_endian() ^ impl->refin;

    for (crc_u16 byte = 0; byte < CRC_U8_COUNT; ++byte) {
        crc_u64 accum = impl->bytewise[byte];
        crc_u64 value = accum;
        if (byteswap) {
            value = crc_u64_byteswap(value);
        }
        table[byte] = value;

        for (crc_u16 slice = 1; slice < CRC_MAX_SIZE; ++slice) {
            if (impl->refin) {
                crc_u64 upper = accum >> CRC_U8_WIDTH;
                crc_u64 lower = accum;
                lower = impl->bytewise[lower & CRC_U8_MASK];
                accum = lower ^ upper;
            }
            else {
                crc_u64 lower = accum << CRC_U8_WIDTH;
                crc_u64 upper = accum >> (CRC_U64_LEAST - CRC_U8_WIDTH);
                upper = impl->bytewise[upper & CRC_U8_MASK];
                accum = lower ^ upper;
            }
            crc_u32 index = ((crc_u32)CRC_U8_COUNT * slice) + byte;
            value = accum;
            if (byteswap) {
                value = crc_u64_byteswap(value);
            }
            table[index] = value;
        }
    }
}


static crc_u64
crcu64_combine(crcu64_impl *impl, crc_u64 crc1, crc_u64 crc2, size_t len2)
{
    assert(impl);
    assert(crc1 <= crc_u64_bitmask(impl->width));
    assert(crc2 <= crc_u64_bitmask(impl->width));
    if (!len2) {
        return crc1;
    }
    /* There are much faster algorithms! */
    crc_u64 dirty_ = impl->dirty;  /* backup */
    crc_u64 accum_ = impl->accum;  /* backup */

    crc1 ^= impl->xorout;  /* undo */
    crc2 ^= impl->xorout;  /* undo */

    if (impl->refout) {
        crc_u8 width = impl->width;
        crc1 = crc_u64_bitswap(crc1, width);  /* undo */
        crc2 = crc_u64_bitswap(crc2, width);  /* undo */
    }

    crcu64_impl_clear_init(impl, crc1);
    impl->accum ^= impl->init;  /* undo */
    crcu64_impl_zero_bytes(impl, len2);
    crc_u64 accum1 = impl->accum;

    crcu64_impl_clear_init(impl, crc2);
    crc_u64 accum2 = impl->accum;

    impl->accum = accum1 ^ accum2;
    impl->dirty = 1;
    crc_u64 crc = crcu64_impl_digest(impl);

    impl->accum = accum_;  /* restore */
    impl->dirty = dirty_;  /* restore */
    return crc;
}


/* ================================================================ */
/* Module types */

/* CRC object status variables */
typedef struct {
    PyObject_HEAD
    PyObject *tabbuf_bytes;     /* PyByteArrayObject */
    PyObject *tabbuf_words;     /* PyByteArrayObject */
    crcu64_impl impl;
    /* Prevents undefined behavior via multiple threads entering the C API. */
    PyMutex mutex;
    bool use_mutex;
} crcu64object;


/* Module state variables */
typedef struct {
    PyObject *id_name_default;          /* PyUnicodeObject */
    PyObject *crcu64_type;              /* PyTypeObject */
    PyObject *crcu64_bytewise_cache;    /* PyDictObject */
    PyObject *crcu64_wordwise_cache;    /* PyDictObject */
} crcmodule_state;


#include "clinic/crcmodule.c.h"


/* Gets the module state from the module object */
static crcmodule_state *
crcmodule_get_state(PyObject *module)
{
    assert(module);
    void *state = PyModule_GetState(module);
    assert(state);
    return (crcmodule_state *)state;
}


/* ================================================================ */
/* CRC object type method implementations */

/* Allocates and initializes a new CRC object */
static crcu64object *
_crc_crcu64_type_new(crcmodule_state *state)
{
    assert(state);
    assert(state->crcu64_type);
    PyTypeObject *crcu64_type = (PyTypeObject *)state->crcu64_type;
    crcu64object *new = PyObject_GC_New(crcu64object, crcu64_type);
    if (new) {
        new->tabbuf_bytes = NULL;
        new->tabbuf_words = NULL;
        crcu64_impl_ctor(&new->impl);
        HASHLIB_INIT_MUTEX(new);
        PyObject_GC_Track(new);
    }
    return new;
}


/* Returns the internal result as an integer object */
static PyObject *
_crc_crcu64_type_index(crcu64object *self)
{
    assert(self);
    ENTER_HASHLIB(self);
    crcu64_impl *impl = &self->impl;
    crc_u64 result = crcu64_impl_digest(impl);
    PyObject *return_value = PyLong_FromUnsignedLongLong(result);
    LEAVE_HASHLIB(self);
    return return_value;
}


/* Deallocates a CRC object */
static void
_crc_crcu64_type_dealloc(crcu64object *self)
{
    assert(self);
    Py_CLEAR(self->tabbuf_bytes);
    Py_CLEAR(self->tabbuf_words);
    self->impl.bytewise = NULL;
    self->impl.wordwise = NULL;
    PyTypeObject *tp = Py_TYPE((PyObject *)self);
    PyObject_GC_UnTrack(self);
    PyObject_GC_Del(self);
    Py_DECREF(tp);
}


/* Traverses the CRC object type */
static int
_crc_crcu64_type_traverse(PyObject *ptr, visitproc visit, void *arg)
{
    Py_VISIT(Py_TYPE(ptr));
    return 0;
}


/* ---------------------------------------------------------------- */
/* CRC object method implementations */

/*[clinic input]
_crc.crcu64.combine

    crc1: unsigned_long_long
        CRC result of the first part.

    crc2: unsigned_long_long
        CRC result of the second part.

    len2: size_t
        Length of the second part, in bytes.
    /

Return the combined CRC of the two parts.

The CRC of the two parts must be generated by the same configuration of this
CRC object.
This method leaves the internal state of the CRC object unchanged.
[clinic start generated code]*/

static PyObject *
_crc_crcu64_combine_impl(crcu64object *self, unsigned long long crc1,
                         unsigned long long crc2, size_t len2)
/*[clinic end generated code: output=8d8c663891d02806 input=a4e0c5cd3b772983]*/
{
    assert(self);
    ENTER_HASHLIB(self);
    crcu64_impl *impl = &self->impl;
    crcu64_impl local;
    crcu64_impl_copy(&local, impl);
    LEAVE_HASHLIB(self);

    crc_u64 mask = crc_u64_bitmask(local.width);
    if (crc1 > mask) {
        PyErr_SetString(PyExc_OverflowError, "crc1 out of range");
        return NULL;
    }
    if (crc2 > mask) {
        PyErr_SetString(PyExc_OverflowError, "crc2 out of range");
        return NULL;
    }
    crc_u64 crc = crcu64_combine(&local, (crc_u64)crc1, (crc_u64)crc2, len2);
    return PyLong_FromUnsignedLongLong(crc);
}


/*[clinic input]
_crc.crcu64.copy

    cls: defining_class

Return a copy of the CRC object.
[clinic start generated code]*/

static PyObject *
_crc_crcu64_copy_impl(crcu64object *self, PyTypeObject *cls)
/*[clinic end generated code: output=5bae89457465e8cd input=921ecf1870886ae6]*/
{
    assert(self);
    assert(cls);
    crcmodule_state *state = PyType_GetModuleState(cls);
    crcu64object *copied = _crc_crcu64_type_new(state);
    if (copied)
    {
        ENTER_HASHLIB(self);
        Py_XINCREF(self->tabbuf_bytes);
        copied->tabbuf_bytes = self->tabbuf_bytes;
        Py_XINCREF(self->tabbuf_words);
        copied->tabbuf_words = self->tabbuf_words;
        crcu64_impl_copy(&copied->impl, &self->impl);
        LEAVE_HASHLIB(self);
    }
    return (PyObject *)copied;
}


/*[clinic input]
_crc.crcu64.digest

Return the digest value as a bytes object.
[clinic start generated code]*/

static PyObject *
_crc_crcu64_digest_impl(crcu64object *self)
/*[clinic end generated code: output=887f6f1fc01c4ec4 input=a6828c013b9ac578]*/
{
    assert(self);
    ENTER_HASHLIB(self);
    crcu64_impl *impl = &self->impl;
    crc_u64 result = crcu64_impl_digest(impl);
    crc_u8 width = impl->width;
    LEAVE_HASHLIB(self);

    size_t size = (width + (CRC_U8_WIDTH - 1)) / CRC_U8_WIDTH;
    crc_u8 buffer[CRC_MAX_SIZE] = {0};

    for (crc_u16 i = CRC_MAX_SIZE; i--; /**/) {
        buffer[i] = (crc_u8)(result & CRC_U8_MASK);
        result >>= CRC_U8_WIDTH;
    }
    crc_u8 *data = &buffer[CRC_MAX_SIZE - size];
    return PyBytes_FromStringAndSize((char *)data, (Py_ssize_t)size);
}


/*[clinic input]
_crc.crcu64.hexdigest

Return the digest value as a string of hexadecimal digits.
[clinic start generated code]*/

static PyObject *
_crc_crcu64_hexdigest_impl(crcu64object *self)
/*[clinic end generated code: output=0123b0ea732a8e50 input=eff0bc610ee0130e]*/
{
    assert(self);
    ENTER_HASHLIB(self);
    crcu64_impl *impl = &self->impl;
    crc_u64 result = crcu64_impl_digest(impl);
    crc_u8 width = impl->width;
    LEAVE_HASHLIB(self);

    const char *const hexchars = "0123456789abcdef";
    size_t size = (width + (4 - 1)) / 4;
    size += size & 1;
    char buffer[CRC_MAX_NIBBLE] = {0};

    for (crc_u16 i = CRC_MAX_SIZE; i--; /**/) {
        for (crc_u16 j = CRC_U8_NIBBLE; j--; /**/) {
            buffer[i*CRC_U8_NIBBLE + j] = hexchars[result & 0xF];
            result >>= 4;
        }
    }
    char *data = &buffer[CRC_MAX_NIBBLE - size];
    return PyUnicode_FromStringAndSize(data, (Py_ssize_t)size);
}


/*[clinic input]
_crc.crcu64.clear

    init: object(c_default="NULL") = None
        Initial CRC value.
    /

Reset internal computations.

Computations resume from the provided initial value, or the default if not
provided instead.
[clinic start generated code]*/

static PyObject *
_crc_crcu64_clear_impl(crcu64object *self, PyObject *init)
/*[clinic end generated code: output=6fbe9b640ca80ecb input=fe133fd3baa6cda2]*/
{
    assert(self);
    crc_u64 init_ = 0;
    if (init && !Py_IsNone(init)) {
        CHECK_U64(init_ = PyLong_AsUnsignedLongLong(init));
    } else {
        init = NULL;
    }

    ENTER_HASHLIB(self);
    crcu64_impl *impl = &self->impl;
    if (init) {
        crcu64_impl_clear_init(impl, init_);
    } else {
        crcu64_impl_clear_default(impl);
    }
    LEAVE_HASHLIB(self);
    Py_RETURN_NONE;
error:
    return NULL;
}


/*[clinic input]
_crc.crcu64.update

    data: Py_buffer
    /

Update this object's state with the provided string.

For each input byte, any bits above the configured CRC bit width are ignored.
[clinic start generated code]*/

static PyObject *
_crc_crcu64_update_impl(crcu64object *self, Py_buffer *data)
/*[clinic end generated code: output=0fea364a064b7f8a input=d423ed3ad74bcbbb]*/
{
    assert(self);
    assert(data);
    if (data->len >= HASHLIB_GIL_MINSIZE) {
        self->use_mutex = true;
    }
    crcu64_impl *impl = &self->impl;
    if (self->use_mutex) {
        Py_BEGIN_ALLOW_THREADS
        PyMutex_Lock(&self->mutex);
        crcu64_impl_update(impl, data->buf, (size_t)data->len);
        PyMutex_Unlock(&self->mutex);
        Py_END_ALLOW_THREADS
    } else {
        crcu64_impl_update(impl, data->buf, (size_t)data->len);
    }
    Py_RETURN_NONE;
}


/*[clinic input]
_crc.crcu64.update_word

    word: unsigned_long_long
        Integer data word to feed to the CRC algorithm.
        Any bits above width are ignored.

    width: int
        Number of data word bits to process, up to the configured CRC width.
    /

Update this object's state with the provided word.
[clinic start generated code]*/

static PyObject *
_crc_crcu64_update_word_impl(crcu64object *self, unsigned long long word,
                             int width)
/*[clinic end generated code: output=915cd43b2581ff4a input=53481cfa9597be23]*/
{
    assert(self);
    if ((width < 0) || (width > CRC_MAX_WIDTH)) {
        PyErr_SetString(PyExc_OverflowError, "width out of range");
        return NULL;
    }

    ENTER_HASHLIB(self);
    crcu64_impl *impl = &self->impl;
    crcu64_impl_update_word(impl, (crc_u64)word, (crc_u8)width);
    LEAVE_HASHLIB(self);
    Py_RETURN_NONE;
}


/*[clinic input]
_crc.crcu64.zero_bits

    numbits: size_t
        Number of input bits.
    /

Update this object's state with a number of zero (NULL) bits.
[clinic start generated code]*/

static PyObject *
_crc_crcu64_zero_bits_impl(crcu64object *self, size_t numbits)
/*[clinic end generated code: output=8f50a7b873f516cc input=bf1fd1cefdbffcb8]*/
{
    assert(self);
    if (numbits >= ((size_t)HASHLIB_GIL_MINSIZE * CRC_U8_WIDTH)) {
        self->use_mutex = true;
    }
    crcu64_impl *impl = &self->impl;
    if (self->use_mutex) {
        Py_BEGIN_ALLOW_THREADS
        PyMutex_Lock(&self->mutex);
        crcu64_impl_zero_bits(impl, numbits);
        PyMutex_Unlock(&self->mutex);
        Py_END_ALLOW_THREADS
    } else {
        crcu64_impl_zero_bits(impl, numbits);
    }
    Py_RETURN_NONE;
}


/*[clinic input]
_crc.crcu64.zero_bytes

    numbytes: size_t
        Number of input bytes.
    /

Update this object's state with a number of zero (NULL) bytes.
[clinic start generated code]*/

static PyObject *
_crc_crcu64_zero_bytes_impl(crcu64object *self, size_t numbytes)
/*[clinic end generated code: output=3171787247802f74 input=9eb48db7400afe74]*/
{
    assert(self);
    if (numbytes >= HASHLIB_GIL_MINSIZE) {
        self->use_mutex = true;
    }
    crcu64_impl *impl = &self->impl;
    if (self->use_mutex) {
        Py_BEGIN_ALLOW_THREADS
        PyMutex_Lock(&self->mutex);
        crcu64_impl_zero_bytes(impl, numbytes);
        PyMutex_Unlock(&self->mutex);
        Py_END_ALLOW_THREADS
    } else {
        crcu64_impl_zero_bytes(impl, numbytes);
    }
    Py_RETURN_NONE;
}


/* CRC obejct methods table */
static PyMethodDef _crc_crcu64_type_methods[] = {
    _CRC_CRCU64_CLEAR_METHODDEF
    _CRC_CRCU64_COMBINE_METHODDEF
    _CRC_CRCU64_COPY_METHODDEF
    _CRC_CRCU64_DIGEST_METHODDEF
    _CRC_CRCU64_HEXDIGEST_METHODDEF
    _CRC_CRCU64_UPDATE_METHODDEF
    _CRC_CRCU64_UPDATE_WORD_METHODDEF
    _CRC_CRCU64_ZERO_BITS_METHODDEF
    _CRC_CRCU64_ZERO_BYTES_METHODDEF
    { NULL, NULL, 0, NULL }  /* sentinel */
};


/* ---------------------------------------------------------------- */
/* CRC object getter/setter methods */

/* Gets the digest byte size */
static PyObject *
_crc_crcu64_get_digest_size(crcu64object *self, void *)
{
    return PyLong_FromSize_t(CRC_MAX_SIZE);
}


/* Gets the block byte size */
static PyObject *
_crc_crcu64_get_block_size(crcu64object *self, void *)
{
    return PyLong_FromSize_t(1);
}


/* Gets the constructor name */
static PyObject *
_crc_crcu64_get_name(crcu64object *self, void *)
{
    return PyUnicode_FromStringAndSize("crc", 3);
}


/* Gets the configured CRC bit width */
static PyObject *
_crc_crcu64_get_width(crcu64object *self, void *)
{
    assert(self);
    ENTER_HASHLIB(self);
    const crcu64_impl *impl = &self->impl;
    crc_u8 width = impl->width;
    LEAVE_HASHLIB(self);
    return PyLong_FromUnsignedLong(width);
}


/* Gets the configured CRC polynomial */
static PyObject *
_crc_crcu64_get_poly(crcu64object *self, void *)
{
    assert(self);
    ENTER_HASHLIB(self);
    const crcu64_impl *impl = &self->impl;
    crc_u64 poly = crcu64_impl_externalize(impl, impl->poly);
    LEAVE_HASHLIB(self);
    return PyLong_FromUnsignedLongLong(poly);
}


/* Gets the configured CRC init (initial value) */
static PyObject *
_crc_crcu64_get_init(crcu64object *self, void *)
{
    assert(self);
    ENTER_HASHLIB(self);
    const crcu64_impl *impl = &self->impl;
    crc_u64 init = crcu64_impl_externalize(impl, impl->init);
    LEAVE_HASHLIB(self);
    return PyLong_FromUnsignedLongLong(init);
}


/* Gets the configured CRC input reflection option */
static PyObject *
_crc_crcu64_get_refin(crcu64object *self, void *)
{
    assert(self);
    ENTER_HASHLIB(self);
    const crcu64_impl *impl = &self->impl;
    crc_u8 refin = impl->refin;
    LEAVE_HASHLIB(self);
    return refin ? Py_True : Py_False;
}


/* Gets the configured CRC output reflection option */
static PyObject *
_crc_crcu64_get_refout(crcu64object *self, void *)
{
    assert(self);
    ENTER_HASHLIB(self);
    const crcu64_impl *impl = &self->impl;
    crc_u8 refout = impl->refout;
    LEAVE_HASHLIB(self);
    return refout ? Py_True : Py_False;
}


/* Gets the configured CRC output XOR mask */
static PyObject *
_crc_crcu64_get_xorout(crcu64object *self, void *)
{
    assert(self);
    ENTER_HASHLIB(self);
    const crcu64_impl *impl = &self->impl;
    crc_u64 xorout = impl->xorout;
    LEAVE_HASHLIB(self);
    return PyLong_FromUnsignedLongLong(xorout);
}


/* CRC object type getter/setter table */
static PyGetSetDef _crc_crcu64_type_getset[] = {
    { "digest_size", (getter)_crc_crcu64_get_digest_size, NULL, NULL, NULL },
    { "block_size",  (getter)_crc_crcu64_get_block_size,  NULL, NULL, NULL },
    { "name",        (getter)_crc_crcu64_get_name,        NULL, NULL, NULL },
    { "width",       (getter)_crc_crcu64_get_width,       NULL, NULL, NULL },
    { "poly",        (getter)_crc_crcu64_get_poly,        NULL, NULL, NULL },
    { "init",        (getter)_crc_crcu64_get_init,        NULL, NULL, NULL },
    { "refin",       (getter)_crc_crcu64_get_refin,       NULL, NULL, NULL },
    { "refout",      (getter)_crc_crcu64_get_refout,      NULL, NULL, NULL },
    { "xorout",      (getter)_crc_crcu64_get_xorout,      NULL, NULL, NULL },
    { NULL, NULL, NULL, NULL, NULL }  /* sentinel */
};


/* ---------------------------------------------------------------- */

/* CRC object type slots table */
static PyType_Slot _crc_crcu64_type_slots[] = {
    { Py_nb_index,    _crc_crcu64_type_index },
    { Py_tp_dealloc,  _crc_crcu64_type_dealloc },
    { Py_tp_getset,   _crc_crcu64_type_getset },
    { Py_tp_methods,  _crc_crcu64_type_methods },
    { Py_tp_traverse, _crc_crcu64_type_traverse },
    { 0, NULL }  /* sentinel */
};


/* CRC object type specification */
static PyType_Spec _crc_crcu64_type_spec = {
    .name = "_crc.crcu64",
    .basicsize = sizeof(crcu64object),
    .flags = (Py_TPFLAGS_DEFAULT |
              Py_TPFLAGS_DISALLOW_INSTANTIATION |
              Py_TPFLAGS_IMMUTABLETYPE |
              Py_TPFLAGS_HAVE_GC),
    .slots = _crc_crcu64_type_slots
};


/* ================================================================ */
/* Module helper functions */

/* Finds a named template and applies it */
static int
crc_apply_config_name(crc_config *config, PyObject *name)
{
    assert(config);
    if (!name || Py_IsNone(name)) {
        return 0;
    }
    PyObject *bytes = NULL;
    if (!PyUnicode_Check(name)) {
        PyErr_SetString(PyExc_TypeError, "name must be a string");
        goto error;
    }
    bytes = PyUnicode_AsASCIIString(name);
    const crc_config *found = crc_find_config(PyBytes_AS_STRING(bytes));
    if (!found) {
        PyErr_SetString(PyExc_KeyError, "unknown template name");
        goto error;
    }

    config->poly   = found->poly;
    config->init   = found->init;
    config->xorout = found->xorout;
    config->width  = found->width;
    config->refin  = found->refin;
    config->refout = found->refout;

    Py_DECREF(bytes);
    return 0;
error:
    Py_XDECREF(bytes);
    return -1;
}


/* Applies the width argument to a configuration */
static int
crc_apply_config_width(crc_config *config, PyObject *width)
{
    assert(config);
    if (width && !Py_IsNone(width)) {
        crc_u64 width_ = PyLong_AsUnsignedLongLong(width);
        CHECK_U64(width_);
        if (!width_ || (width_ > CRC_MAX_WIDTH)) {
            PyErr_SetString(PyExc_OverflowError, "width out of range");
            goto error;
        }
        config->width = (crc_u8)width_;
    }
    if (!config->width) {
        PyErr_SetString(PyExc_OverflowError, "width required");
        goto error;
    }
    return 0;
error:
    return -1;
}


/* Applies the poly argument to a configuration */
static int
crc_apply_config_poly(crc_config *config, PyObject *poly)
{
    assert(config);
    if (poly && !Py_IsNone(poly)) {
        crc_u64 poly_ = PyLong_AsUnsignedLongLong(poly);
        CHECK_U64(poly_);
        config->poly = poly_;
    }
    if (!config->poly) {
        PyErr_SetString(PyExc_OverflowError, "poly required");
        goto error;
    }
    return 0;
error:
    return -1;
}


/* Applies the init argument to a configuration */
static int
crc_apply_config_init(crc_config *config, PyObject *init)
{
    assert(config);
    if (init && !Py_IsNone(init)) {
        crc_u64 init_ = PyLong_AsUnsignedLongLong(init);
        CHECK_U64(init_);
        config->init = init_;
    }
    return 0;
error:
    return -1;
}


/* Applies a refin argument to a configuration */
static int
crc_apply_config_refin(crc_config *config, PyObject *refin)
{
    assert(config);
    if (refin && !Py_IsNone(refin)) {
        int truth = PyObject_IsTrue(refin);
        if (truth < 0) {
            goto error;
        }
        config->refin = (crc_u8)truth;
    }
    return 0;
error:
    return -1;
}


/* Applies a refout argument to a configuration */
static int
crc_apply_config_refout(crc_config *config, PyObject *refout)
{
    assert(config);
    if (refout && !Py_IsNone(refout)) {
        int truth = PyObject_IsTrue(refout);
        if (truth < 0) {
            goto error;
        }
        config->refout = (crc_u8)truth;
    }
    return 0;
error:
    return -1;
}


/* Applies the xorout argument to a configuration */
static int
crc_apply_config_xorout(crc_config *config, PyObject *xorout)
{
    assert(config);
    if (xorout && !Py_IsNone(xorout)) {
        crc_u64 xorout_ = PyLong_AsUnsignedLongLong(xorout);
        CHECK_U64(xorout_);
        config->xorout = xorout_;
    }
    return 0;
error:
    return -1;
}


/* Parses the method argument */
static int
crc_parse_method(PyObject *method, crc_u8 *chosen)
{
    assert(chosen);
    *chosen = CRC_METHOD_BITWISE;
    if (method && !Py_IsNone(method)) {
        if (!PyUnicode_Check(method)) {
            PyErr_SetString(PyExc_TypeError, "method must be a string");
            goto error;
        }
        else if (_PyUnicode_Equal(method, &_Py_ID(bitwise))) {
            ;
        }
        else if (_PyUnicode_Equal(method, &_Py_ID(bytewise))) {
            *chosen = CRC_METHOD_BYTEWISE;
        }
        else if (_PyUnicode_Equal(method, &_Py_ID(wordwise))) {
            *chosen = CRC_METHOD_BYTEWISE | CRC_METHOD_WORDWISE;
        }
        else {
            PyErr_SetString(PyExc_KeyError, "unknown method");
            goto error;
        }
    }
    else {
        *chosen = CRC_METHOD_BYTEWISE | CRC_METHOD_WORDWISE;
    }
    return 0;
error:
    return -1;
}


/* Applies the provided method to a CRC object */
static int
crcu64_apply_method(crcu64object *self,
                    crc_u8 method,
                    crc_config *config,
                    crcmodule_state *state)
{
    assert(self);
    assert((method == CRC_METHOD_BYTEWISE) ||
           (method == CRC_METHOD_WORDWISE));
    assert(config);
    PyObject *tabkey = NULL;
    PyObject *tabbuf = NULL;
    crcu64_impl *impl = &self->impl;
    crc_u8 slices;
    CHECK(tabkey = PyBytes_FromStringAndSize(
        (char *)config, (Py_ssize_t)sizeof(crc_config)));
    PyObject *cache;
    if (method == CRC_METHOD_WORDWISE) {
        impl->update = crcu64_impl_update_wordwise;
        cache = (PyObject *)state->crcu64_wordwise_cache;
        slices = 8;
    }
    else {
        impl->update = crcu64_impl_update_bytewise;
        cache = (PyObject *)state->crcu64_bytewise_cache;
        slices = 1;
    }
    assert(cache);
    int got = PyDict_GetItemRef(cache, tabkey, &tabbuf);
    CHECK(got >= 0);
    if (got) {
        if (!PyByteArray_CheckExact(tabbuf)) {
            PyErr_SetString(PyExc_RuntimeError, "unexpected table type");
            goto error;
        }
        Py_INCREF(tabbuf);
        if (method == CRC_METHOD_WORDWISE) {
            Py_CLEAR(self->tabbuf_words);
            self->tabbuf_words = tabbuf;
            impl->wordwise = (crc_u64 *)PyByteArray_AS_STRING(tabbuf);
        }
        else {
            Py_CLEAR(self->tabbuf_bytes);
            self->tabbuf_bytes = tabbuf;
            impl->bytewise = (crc_u64 *)PyByteArray_AS_STRING(tabbuf);
        }
    }
    else {
        Py_ssize_t tabsize = (Py_ssize_t)
            (slices * CRC_U8_COUNT * sizeof(crc_u64));
        CHECK(tabbuf = PyByteArray_FromStringAndSize(NULL, tabsize));
        Py_INCREF(tabbuf);
        if (method == CRC_METHOD_WORDWISE) {
            Py_CLEAR(self->tabbuf_words);
            self->tabbuf_words = tabbuf;
            impl->wordwise = (crc_u64 *)PyByteArray_AS_STRING(tabbuf);
            crcu64_impl_tabulate_wordwise(impl);
        }
        else {
            Py_CLEAR(self->tabbuf_bytes);
            self->tabbuf_bytes = tabbuf;
            impl->bytewise = (crc_u64 *)PyByteArray_AS_STRING(tabbuf);
            crcu64_impl_tabulate_bytewise(impl);
        }
        (void)PyDict_SetItem(cache, tabkey, tabbuf);
    }
    Py_DECREF(tabkey);
    Py_DECREF(tabbuf);
    return 0;
error:
    Py_XDECREF(tabkey);
    Py_XDECREF(tabbuf);
    return -1;
}

/* ---------------------------------------------------------------- */
/* Module functions */

/*[clinic input]
_crc.crc

    data: Py_buffer = None
        Byte string to update after initialization.
    *
    name: object(c_default="NULL") = None
        Template configuration name.
        If no other options are provided, default to "crc-32".

    width: object(c_default="NULL") = None
        CRC bit width, between 1 and MAX_WIDTH.
        Mandatory if no name is provided.

    poly: object(c_default="NULL") = None
        CRC polynomial, between 1 and the maximum for the configured width.
        Mandatory if no name is provided.

    init: object(c_default="NULL") = None
        CRC initial value, compatible with the configured width.

    refin: object(c_default="NULL") = None
        Reversing input bits, across most and least significant bits; bool.

    refout: object(c_default="NULL") = None
        Reversing output bits, across most and least significant bits; bool.

    xorout: object(c_default="NULL") = None
        Output result inversion bit mask. Applied after output bit reversal.

    method: unicode(c_default="NULL") = "wordwise"
        Algorithm method, one of: "bitwise", "bytewise", "wordwise".

    usedforsecurity: bool = False
        Ignored. Please leave it false, because a CRC is not secure.

Return a new CRC object; optionally initialized with a byte string.
[clinic start generated code]*/

static PyObject *
_crc_crc_impl(PyObject *module, Py_buffer *data, PyObject *name,
              PyObject *width, PyObject *poly, PyObject *init,
              PyObject *refin, PyObject *refout, PyObject *xorout,
              PyObject *method, int usedforsecurity)
/*[clinic end generated code: output=7e4a9f8c97f8d047 input=c01025bd92ab61d3]*/
{
    crcu64object *newu64 = NULL;
    crc_config config = {0};
    crcmodule_state *state = crcmodule_get_state(module);
    (void)usedforsecurity;

    if (!name && !width && !poly && !init && !refin && !refout && !xorout) {
        name = state->id_name_default;
    }
    CHECK(!crc_apply_config_name(&config, name));
    CHECK(!crc_apply_config_width(&config, width));
    CHECK(!crc_apply_config_poly(&config, poly));
    CHECK(!crc_apply_config_init(&config, init));
    CHECK(!crc_apply_config_refin(&config, refin));
    CHECK(!crc_apply_config_refout(&config, refout));
    CHECK(!crc_apply_config_xorout(&config, xorout));

    CHECK(newu64 = _crc_crcu64_type_new(state));
    crcu64_impl *impl = &newu64->impl;
    const char *errstr = crcu64_impl_configure(impl, &config);
    if (errstr) {
        PyErr_SetString(PyExc_OverflowError, errstr);
        goto error;
    }
    crc_u8 method_ = CRC_METHOD_BITWISE;
    CHECK(!crc_parse_method(method, &method_));
    const crc_u8 bytewise = CRC_METHOD_BYTEWISE;
    if (method_ & bytewise) {
        CHECK(!crcu64_apply_method(newu64, bytewise, &config, state));
    }
    const crc_u8 wordwise = CRC_METHOD_WORDWISE;
    if (method_ & wordwise) {
        CHECK(!crcu64_apply_method(newu64, wordwise, &config, state));
    }

    if (data) {
        if (data->len >= HASHLIB_GIL_MINSIZE) {
            /* We do not initialize self->lock here as this is the constructor
             * where it is not yet possible to have concurrent access. */
            Py_BEGIN_ALLOW_THREADS
            crcu64_impl_update(impl, data->buf, data->len);
            Py_END_ALLOW_THREADS
        } else {
            crcu64_impl_update(impl, data->buf, data->len);
        }
    }

    CHECK(!PyErr_Occurred());
    goto finally;
error:
    Py_CLEAR(newu64);
finally:
    return (PyObject *)newu64;
}


/*[clinic input]
_crc.templates_available

Return a dict of available templates.

Each template is a tuple (width, poly, init, refin, refout, xorout)
(see `_crc.crc` for their meaning), mapped by the template name.
[clinic start generated code]*/

static PyObject *
_crc_templates_available_impl(PyObject *module)
/*[clinic end generated code: output=649ae2b936b1757a input=36dc8fef499acc58]*/
{
    (void)crcmodule_get_state(module);
    return crc_templates_dict();
}


/* Module methods table */
static PyMethodDef crcmodule_methods[] = {
    _CRC_CRC_METHODDEF
    _CRC_TEMPLATES_AVAILABLE_METHODDEF
    { NULL, NULL, 0, NULL }  /* sentinel */
};


/* ---------------------------------------------------------------- */

/* Module execution function */
static int
crcmodule_exec(PyObject *module)
{
    crcmodule_state *state = crcmodule_get_state(module);

    CHECK(!PyModule_AddIntConstant(module, "BYTE_WIDTH", (int)CRC_U8_WIDTH));
    CHECK(!PyModule_AddIntConstant(module, "MAX_WIDTH", (int)CRC_MAX_WIDTH));

    crc_u64 mask = crc_u64_bitmask(CRC_MAX_WIDTH);
    PyObject *max_value = PyLong_FromUnsignedLongLong(mask);
    CHECK(max_value);
    CHECK(!PyModule_Add(module, "MAX_VALUE", max_value));

    CHECK(state->id_name_default = PyUnicode_FromString(CRC_NAME_DEFAULT));

    CHECK(state->crcu64_type = PyType_FromModuleAndSpec(
        module, &_crc_crcu64_type_spec, NULL));
    CHECK(!PyModule_AddType(module, (PyTypeObject *)state->crcu64_type));

    CHECK(state->crcu64_bytewise_cache = PyDict_New());
    CHECK(state->crcu64_wordwise_cache = PyDict_New());

    return 0;
error:
    return -1;
}


/* Modules slots table */
static PyModuleDef_Slot crcmodule_slots[] = {
    { Py_mod_exec, crcmodule_exec },
    { Py_mod_multiple_interpreters, Py_MOD_PER_INTERPRETER_GIL_SUPPORTED },
    { Py_mod_gil, Py_MOD_GIL_NOT_USED },
    { 0, NULL }  /* sentinel */
};


/* ---------------------------------------------------------------- */

/* Traverses the module state */
static int
crcmodule_traverse(PyObject *module, visitproc visit, void *arg)
{
    crcmodule_state *state = crcmodule_get_state(module);
    Py_VISIT(state->id_name_default);
    Py_VISIT(state->crcu64_type);
    Py_VISIT(state->crcu64_bytewise_cache);
    Py_VISIT(state->crcu64_wordwise_cache);
    return 0;
}


/* Clears the module state */
static int
crcmodule_clear(PyObject *module)
{
    crcmodule_state *state = crcmodule_get_state(module);
    Py_CLEAR(state->id_name_default);
    Py_CLEAR(state->crcu64_type);
    Py_CLEAR(state->crcu64_bytewise_cache);
    Py_CLEAR(state->crcu64_wordwise_cache);
    return 0;
}


/* Frees the module state */
static void
crcmodule_free(void *module)
{
    (void)crcmodule_clear((PyObject *)module);
}


/* Module specification */
static struct PyModuleDef crcmodule = {
    .m_base     = PyModuleDef_HEAD_INIT,
    .m_name     = "_crc",
    .m_doc      = NULL,
    .m_size     = sizeof(crcmodule_state),
    .m_methods  = crcmodule_methods,
    .m_slots    = crcmodule_slots,
    .m_traverse = crcmodule_traverse,
    .m_clear    = crcmodule_clear,
    .m_free     = crcmodule_free
};


/* Initializes the module */
PyMODINIT_FUNC
PyInit__crc(void)
{
    return PyModuleDef_Init(&crcmodule);
}


/* ================================================================ */

#undef CHECK
#undef CHECK_U64
