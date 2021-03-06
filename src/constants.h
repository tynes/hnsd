#ifndef _HSK_CONSTANTS_H
#define _HSK_CONSTANTS_H

#include "genesis.h"

#define HSK_MAIN 0
#define HSK_TESTNET 1
#define HSK_REGTEST 2
#define HSK_SIMNET 3

#ifndef HSK_NETWORK
#define HSK_NETWORK HSK_SIMNET
#endif

#define HSK_MAX_MESSAGE (8 * 1000 * 1000)
#define HSK_USER_AGENT "/hnsd:0.0.0/"
#define HSK_PROTO_VERSION 1
#define HSK_SERVICES 0
#define HSK_MAX_DATA_SIZE 668
#define HSK_MAX_VALUE_SIZE 512

static const uint8_t HSK_ZERO_HASH[32] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

#define HSK_NS_IP "127.0.0.1"
#define HSK_RS_IP "127.0.0.1"
#define HSK_RS_A "127.0.0.1"

static const char HSK_TRUST_ANCHOR[] = ". DS 35215 13 2 "
  "7C50EA94A63AEECB65B510D1EAC1846C973A89D4AB292287D5A4D715136B57A3";

static const char HSK_KSK_2010[] = ". DS 19036 8 2 "
  "49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5";

static const char HSK_KSK_2017[] = ". DS 20326 8 2 "
  "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D";

#if HSK_NETWORK == HSK_MAIN

/*
 * Main
 */

#define HSK_NETWORK_NAME "main"
#define HSK_MAGIC 0xebf10ad8
#define HSK_PORT 12038
#define HSK_NS_PORT 5359
#define HSK_RS_PORT 5360

#define HSK_BITS 0x1d00ffff

static const uint8_t HSK_LIMIT[32] = {
  0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static const uint8_t HSK_CHAINWORK[32] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

#define HSK_TARGET_WINDOW 144
#define HSK_TARGET_SPACING (10 * 60)
#define HSK_TARGET_TIMESPAN (HSK_TARGET_WINDOW * HSK_TARGET_SPACING)
#define HSK_MIN_ACTUAL (HSK_TARGET_TIMESPAN / 4)
#define HSK_MAX_ACTUAL (HSK_TARGET_TIMESPAN * 4)
#define HSK_TREE_INTERVAL 36
#define HSK_TARGET_RESET false
#define HSK_NO_RETARGETTING false
#define HSK_CUCKOO_BITS 30
#define HSK_CUCKOO_SIZE 42
#define HSK_CUCKOO_PERC 50
#define HSK_CUCKOO_LEGACY false
#define HSK_GENESIS HSK_GENESIS_MAIN

#define HSK_USE_CHECKPOINTS false
#define HSK_LAST_CHECKPOINT 0
#define HSK_MAX_TIP_AGE (24 * 60 * 60)
#define HSK_LAUNCH_DATE 0xffffffff

#elif HSK_NETWORK == HSK_TESTNET

/*
 * Testnet
 */

#define HSK_NETWORK_NAME "testnet"
#define HSK_MAGIC 0x09d8647f
#define HSK_PORT 13038
#define HSK_NS_PORT 15359
#define HSK_RS_PORT 15360

// Note: BTC limit. Consider switching to
// this once we have a new miner written.
// #define HSK_BITS 0x1d00ffff
//
// static const uint8_t HSK_LIMIT[32] = {
//   0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
//   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
//   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
//   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
// };

#define HSK_BITS 0x1d300000

static const uint8_t HSK_LIMIT[32] = {
  0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t HSK_CHAINWORK[32] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

#define HSK_TARGET_WINDOW 144
#define HSK_TARGET_SPACING (10 * 60)
#define HSK_TARGET_TIMESPAN (HSK_TARGET_WINDOW * HSK_TARGET_SPACING)
#define HSK_MIN_ACTUAL (HSK_TARGET_TIMESPAN / 4)
#define HSK_MAX_ACTUAL (HSK_TARGET_TIMESPAN * 4)
#define HSK_TREE_INTERVAL 36
#define HSK_TARGET_RESET true
#define HSK_NO_RETARGETTING false
#define HSK_CUCKOO_BITS 24
#define HSK_CUCKOO_SIZE 42
#define HSK_CUCKOO_PERC 50
#define HSK_CUCKOO_LEGACY false
#define HSK_GENESIS HSK_GENESIS_TESTNET

#define HSK_USE_CHECKPOINTS false
#define HSK_LAST_CHECKPOINT 0
#define HSK_MAX_TIP_AGE (2 * 7 * 24 * 60 * 60)
#define HSK_LAUNCH_DATE 0xffffffff

#elif HSK_NETWORK == HSK_REGTEST

/*
 * Regtest
 */

#define HSK_NETWORK_NAME "regtest"
#define HSK_MAGIC 0xbcf173aa
#define HSK_PORT 14038
#define HSK_NS_PORT 25359
#define HSK_RS_PORT 25360

#define HSK_BITS 0x207fffff

static const uint8_t HSK_LIMIT[32] = {
  0x7f, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t HSK_CHAINWORK[32] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

#define HSK_TARGET_WINDOW 144
#define HSK_TARGET_SPACING (10 * 60)
#define HSK_TARGET_TIMESPAN (HSK_TARGET_WINDOW * HSK_TARGET_SPACING)
#define HSK_MIN_ACTUAL (HSK_TARGET_TIMESPAN / 4)
#define HSK_MAX_ACTUAL (HSK_TARGET_TIMESPAN * 4)
#define HSK_TREE_INTERVAL 5
#define HSK_TARGET_RESET true
#define HSK_NO_RETARGETTING true
#define HSK_CUCKOO_BITS 8
#define HSK_CUCKOO_SIZE 4
#define HSK_CUCKOO_PERC 50
#define HSK_CUCKOO_LEGACY false
#define HSK_GENESIS HSK_GENESIS_REGTEST

#define HSK_USE_CHECKPOINTS false
#define HSK_LAST_CHECKPOINT 0
#define HSK_MAX_TIP_AGE (2 * 7 * 24 * 60 * 60)
#define HSK_LAUNCH_DATE 0xffffffff

#elif HSK_NETWORK == HSK_SIMNET

/*
 * Simnet
 */

#define HSK_NETWORK_NAME "simnet"
#define HSK_MAGIC 0x473bd012
#define HSK_PORT 15038
#define HSK_NS_PORT 35359
#define HSK_RS_PORT 35360

#define HSK_BITS 0x207fffff

static const uint8_t HSK_LIMIT[32] = {
  0x7f, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t HSK_CHAINWORK[32] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

#define HSK_TARGET_WINDOW 144
#define HSK_TARGET_SPACING (10 * 60)
#define HSK_TARGET_TIMESPAN (HSK_TARGET_WINDOW * HSK_TARGET_SPACING)
#define HSK_MIN_ACTUAL (HSK_TARGET_TIMESPAN / 4)
#define HSK_MAX_ACTUAL (HSK_TARGET_TIMESPAN * 4)
#define HSK_TREE_INTERVAL 2
#define HSK_TARGET_RESET false
#define HSK_NO_RETARGETTING false
#define HSK_CUCKOO_BITS 16
#define HSK_CUCKOO_SIZE 18
#define HSK_CUCKOO_PERC 50
#define HSK_CUCKOO_LEGACY false
#define HSK_GENESIS HSK_GENESIS_SIMNET

#define HSK_USE_CHECKPOINTS false
#define HSK_LAST_CHECKPOINT 0
#define HSK_MAX_TIP_AGE (2 * 7 * 24 * 60 * 60)
#define HSK_LAUNCH_DATE 0xffffffff

#else

/*
 * Bad Network
 */

#error "Invalid network."

#endif

#endif
