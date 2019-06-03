#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

#include <string.h>
#include <ctype.h>

#include <nfc/nfc.h>

#include "mifare.h"
#include "nfc-utils.h"



static nfc_context *context;
static nfc_device *pnd;
static nfc_target nt;
static mifare_param mp;
static mifare_classic_tag mtKeys;
static mifare_classic_tag mtDump;
static bool bUseKeyA;
static bool bUseKeyFile;
static bool bTolerateFailures;
static bool bForceKeyFile;
static bool magic2 = false;
static uint8_t uiBlocks;

static uint8_t keys[] = {
   0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
   0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7,
   0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
   0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5,
   0x4d, 0x3a, 0x99, 0xc3, 0x51, 0xdd,
   0x1a, 0x98, 0x2c, 0x7e, 0x45, 0x9a,
   0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0xab, 0xcd, 0xef, 0x12, 0x34, 0x56
};

static uint8_t defaultKey = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static uint8_t defaultAcl = {0xff, 0x07, 0x80, 0x69};

static const nfc_modulation nmMifare = {
    .nmt = NMT_ISO14443A,
    .nbr = NBR_106,
};

static size_t num_keys = sizeof(keys)/4;

#define MAX_FRAME_LEN 264

static uint8_t abtRx [MAX_FRAME_LEN];
static int szRxBits;


// uint8_t abHalt[4] = {0x50, 0x00, 0x00,0x00};

static  bool transmit_bits(const uint8_t *pbtTx, const size_t szTxBits)
{
  // Show transmitted command
  printf("Sent bits:     ");
  print_hex_bits(pbtTx, szTxBits);
  // Transmit the bit frame command, we don't use the arbitrary parity feature
  if ((szRxBits = nfc_initiator_transceive_bits(pnd, pbtTx, szTxBits, NULL, abtRx, sizeof(abtRx), NULL)) < 0)
    return false;

  // Show received answer
  printf("Received bits: ");
  print_hex_bits(abtRx, szRxBits);
  // Succesful transfer
  return true;
}

static  bool transmit_bytes(const uint8_t *pbtTx, const size_t szTx)
{
  // Show transmitted command
  printf("Sent bits:     ");
  print_hex(pbtTx, szTx);
  // Transmit the command bytes
  int res;
  if ((res = nfc_initiator_transceive_bytes(pnd, pbtTx, szTx, abtRx, sizeof(abtRx), 0)) < 0)
    return false;

  // Show received answer
  printf("Received bits: ");
  print_hex(abtRx, res);
  // Succesful transfer
  return true;
}

static void
print_success_or_failure(bool bFailure, uint32_t *uiBlockCounter)
{
  printf("%c", (bFailure) ? 'x' : '.');
  if (uiBlockCounter && !bFailure)
    *uiBlockCounter += 1;
}

static bool 
is_first_block(uint32_t uiBlock){
  if (uiBlock < 128)
    return ((uiBlock) % 4 == 0);
  else
    return  ((uiBlock) % 16 == 0);
  }

static bool
is_trailer_block(uint32_t uiBlock){
  if (uiBlock < 128)
    return ((uiBlock + 1) % 16 == 0);
  else
    return ((uiBlock + 1) % 16 == 0);   
}

static  uint32_t
 get_trailer_block(uint32_t uiFirstBlock)
  {
    // Test if we are in the small or big sectors
    uint32_t trailer_block = 0;
      if (uiFirstBlock < 128) {
           trailer_block = uiFirstBlock + (3 - (uiFirstBlock % 4));
      } else {
           trailer_block = uiFirstBlock + (15 - (uiFirstBlock % 16));
      }
      return trailer_block;
  }

static  bool 
authenticate(uint32_t uiBlock)
{
  mifare_cmd mc;
  uint32_t uiTrailerBlock;

  // Set the authentication information (uid)
  memcpy(mp.mpa.abtAuthUid, nt.nti.nai.abtUid + nt.nti.nai.szUidLen - 4, 4);
  
  // Should we use key A or B?
  mc = /*bUseKeyA) ?*/ MC_AUTH_A ;//: MC_AUTH_B;

  // Key file authentication.
  if (mc == MC_AUTH_A) {

    // Locate the trailer (with the keys) used for this sector
    uiTrailerBlock = get_trailer_block(uiBlock);

    // Extract the right key from dump file
    if (mc == MC_AUTH_A)
      memcpy(mp.mpa.abtKey, mtKeys.amb[uiTrailerBlock].mbt.abtKeyA, 6);
    else
      memcpy(mp.mpa.abtKey, mtKeys.amb[uiTrailerBlock].mbt.abtKeyB, 6);

    // Try to authenticate for the current sector
    if (nfc_initiator_mifare_cmd(pnd, mc, uiBlock, &mp))
      return true;

    //network(67,"ffg");
  }

  // If formatting or not using key file, try to guess the right key
  if (!bUseKeyFile) {
    for (size_t key_index = 0; key_index < num_keys; key_index++) {
      memcpy(mp.mpa.abtKey, keys + (key_index * 6), 6);
      if (nfc_initiator_mifare_cmd(pnd, mc, uiBlock, &mp)) {
        if (bUseKeyA)
          memcpy(mtKeys.amb[uiBlock].mbt.abtKeyA, &mp.mpa.abtKey, 6);
        else
          memcpy(mtKeys.amb[uiBlock].mbt.abtKeyB, &mp.mpa.abtKey, 6);
        return true;
      }
      if (nfc_initiator_select_passive_target(pnd, nmMifare, nt.nti.nai.abtUid, nt.nti.nai.szUidLen, NULL) <= 0) {
        ERR("tag was removed");
        return false;
      }
    }
  }

  return false;
}

static int
get_rats(void)
{
  int res;
  uint8_t  abtRats[2] = { 0xe0, 0x50};
  // Use raw send/receive methods
  if (nfc_device_set_property_bool(pnd, NP_EASY_FRAMING, false) < 0) {
    nfc_perror(pnd, "nfc_configure");
    return -1;
  }
  res = nfc_initiator_transceive_bytes(pnd, abtRats, sizeof(abtRats), abtRx, sizeof(abtRx), 0);
  if (res > 0) {
    // ISO14443-4 card, turn RF field off/on to access ISO14443-3 again
    if (nfc_device_set_property_bool(pnd, NP_ACTIVATE_FIELD, false) < 0) {
      nfc_perror(pnd, "nfc_configure");
      return -1;
    }
    if (nfc_device_set_property_bool(pnd, NP_ACTIVATE_FIELD, true) < 0) {
      nfc_perror(pnd, "nfc_configure");
      return -1;
    }
  }
  // Reselect tag
  if (nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, &nt) <= 0) {
    printf("Error: tag disappeared\n");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }
  return res;}


int main () {

  uint8_t *pbtUID;
  nfc_init(&context);
  if (context == NULL) {
    ERR("Unable to init libnfc (malloc)");
    exit(EXIT_FAILURE);
  }

// Try to open the NFC reader
  pnd = nfc_open(context, NULL);
  if (pnd == NULL) {
    ERR("Error opening NFC reader");
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  if (nfc_initiator_init(pnd) < 0) {
    nfc_perror(pnd, "nfc_initiator_init");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  };

// Let the reader only try once to find a tag
  if (nfc_device_set_property_bool(pnd, NP_INFINITE_SELECT, false) < 0) {
    nfc_perror(pnd, "nfc_device_set_property_bool");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }
// Disable ISO14443-4 switching in order to read devices that emulate Mifare Classic with ISO14443-4 compliance.
  if (nfc_device_set_property_bool(pnd, NP_AUTO_ISO14443_4, false) < 0) {
    nfc_perror(pnd, "nfc_device_set_property_bool");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  printf("NFC reader: %s opened\n", nfc_device_get_name(pnd));

// Try to find a MIFARE Classic tag
  int tags;

  tags = nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, &nt);
  if (tags < 0) {
    printf("Error: no tag was found\n");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }
// Test if we are dealing with a MIFARE compatible tag
  if ((nt.nti.nai.btSak & 0x08) == 0) {
    printf("Warning: tag is probably not a MFC!\n");
  }

// Get the info from the current tag
  pbtUID = nt.nti.nai.abtUid;

  printf("Found MIFARE Classic card:\n");
  print_nfc_target(&nt, false);

// Guessing size
  if ((nt.nti.nai.abtAtqa[1] & 0x02) == 0x02 || nt.nti.nai.btSak == 0x18)
// 4K
    uiBlocks = 0xff;
  else if (nt.nti.nai.btSak == 0x09)
// 320b
    uiBlocks = 0x13;
  else
// 1K/2K, checked through RATS
    uiBlocks = 0x3f;
// Testing RATS
  int res;
  if ((res = get_rats()) > 0) {
    if ((res >= 10) && (abtRx[5] == 0xc1) && (abtRx[6] == 0x05)
        && (abtRx[7] == 0x2f) && (abtRx[8] == 0x2f)
        && ((nt.nti.nai.abtAtqa[1] & 0x02) == 0x00)) {
      // MIFARE Plus 2K
      uiBlocks = 0x7f;
    }
    // Chinese magic emulation card, ATS=0978009102:dabc1910
    if ((res == 9)  && (abtRx[5] == 0xda) && (abtRx[6] == 0xbc)
        && (abtRx[7] == 0x19) && (abtRx[8] == 0x10)) {
      magic2 = true;
    }
  }
  printf("Guessing size: seems to be a %lu-byte card\n", (uiBlocks + 1) * sizeof(mifare_classic_block));
  size_t block;
  printf("Input Sector Number: \n");
  nfc_close(pnd);
  nfc_exit(context);
  exit(EXIT_SUCCESS);
}