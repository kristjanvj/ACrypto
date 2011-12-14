 
/* ***********************************************************************************************
 *
 *  ACrypto -- The Arduino Crypto Library
 *
 *  Kristjan V. Jonsson
 *  Kristjan Runarsson
 *  Benedikt Kristinsson 
 *
 *  (c) 2010-2011
 *
 * ***********************************************************************************************
 *
 *  Released under the GNU General Public License v. 3. See <http://www.gnu.org/licenses/gpl.html/>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * **********************************************************************************************
 */
 
/*
 *  This file includes test cases for the Arduino board.
 *  Compile in the Arduino GUI envrionment and upload to a board. We used a Duemilanovae 
 *  with ATMega 328 for our tests. The ACrypto library is actually not specific to the 
 *  Arduino or ATMega processor. Rather, it compiles and executes on a number of platforms.
 *  A test project for a generic PC is included in the library package.
 */
 
/*
 *  This is the header for the ACrypto library. See installation instructions on how to make it accessible to the
 *  Arduino environment.
 */
#include <ACrypto.h>

/*
 *  Define the tests to perform here. 
 *  For some reason the Duemilanovae does not like all the tests to be included at once.
 *  My hunch (unconfirmed) is that it does not like to serial print strings.  Weird things
 *  start to happen if too many strings are present in the source code.
 */
//#define TEST_AES128_CRYPTO
//#define TEST_XTEA_CRYPTO
#define TEST_AES128_CMAC
#define TEST_AES128_CMAC_EtM

/**
 *  Setup the board and perform tests
 */
void setup() {                
  // initialize the digital pin as an output.
  // Pin 13 has an LED connected on most Arduino boards:
  pinMode(13, OUTPUT);     
  
  // Initialize the serial port
  Serial.begin(9600);
  Serial.flush();
  
  delay(5000);
  
  int retcode;
  
  #ifdef  TEST_AES128_CRYPTO
  
  Serial.print("AES128 FIPS ");
  retcode = AES_FIPS_Test();
  if ( retcode!=0 )
  {
    Serial.print("FAILED:"); 
    Serial.println(retcode);
  }
  else
  {
    Serial.println("PASSED");
  }

  Serial.print("AES128 ECB  ");
  retcode = AES_ECB_Test();
  if ( retcode!=0 )
  {
    Serial.print("FAILED:"); 
    Serial.println(retcode);
  }
  else
  {
    Serial.println("PASSED");
  }    
  
  Serial.print("AES128 CBC  ");
  retcode = AES_CBC_Test();
  if ( retcode!=0 )
  {
    Serial.print("FAILED:"); 
    Serial.println(retcode);
  }
  else
  {
    Serial.println("PASSED");
  }

  #endif /* TEST_AES128_CRYPTO */

  #ifdef TEST_XTEA_CRYPTO

  Serial.print("XTEA     ");
  retcode = XTEA_Test();
  if ( retcode!=0 )
  {
    Serial.print("FAILED:"); 
    Serial.println(retcode);
  }
  else
  {
    Serial.println("PASSED");
  }

  Serial.print("XTEA ECB ");
  retcode = XTEA_ECB_Test();
  if ( retcode!=0 )
  {
    Serial.print("FAILED:"); 
    Serial.println(retcode);
  }
  else
  {
    Serial.println("PASSED");
  }

  Serial.print("XTEA CBC ");
  retcode = XTEA_CBC_Test();
  if ( retcode!=0 )
  {
    Serial.print("FAILED:"); 
    Serial.println(retcode);
  }
  else
  {
    Serial.println("PASSED");
  }
  
  #endif /* TEST_XTEA_CRYPTO */

  #ifdef TEST_AES128_CMAC

  Serial.print("AES128-CMAC ");
  retcode = AES128_CMAC_RFC4494_TEST();
  if ( retcode!=0 )
  {
    Serial.print("FAILED:"); 
    Serial.println(retcode);
  }
  else
  {
    Serial.println("PASSED");
  }

  #endif /* TEST_AES128_CMAC */

  #ifdef TEST_AES128_CMAC_EtM

  Serial.print("AES128-CMAC EtM ");
  retcode = AES_CMAC_EtM_Test();
  if ( retcode!=0 )
  {
    Serial.print("FAILED:"); 
    Serial.println(retcode);
  }
  else
  {
    Serial.println("PASSED");
  }
  
  #endif /* TEST_AES128_CMAC_EtM */
}

/**
 *  Loop and blink led 13 once tests are done
 */ 
void loop() {
  digitalWrite(13, HIGH);   // set the LED on
  delay(1000);              // wait for a second
  digitalWrite(13, LOW);    // set the LED off
  delay(1000);              // wait for a second
}

#ifdef DEBUG_PRINT_BYTES
void printBytes(unsigned char *pBytes, int dLength, int linelen=16)
{	 
  for(int i=0; i<dLength;i++)
  {
    if(pBytes[i]<0x10) Serial.print("0");
    Serial.print(pBytes[i],HEX);
    Serial.print(" ");
    if((i+1)%linelen==0 && (i+1)<dLength)
      Serial.print("\n");
  }
  Serial.print("\n");
}
#endif /* DEBUG_PRINT_BYTES */

/**
 *  AES-128 FIPS Test.
 *
 *  This test uses the test vectors from Appendix B of the FIPS-197 (2001) document
 */
int AES_FIPS_Test()
{
  unsigned char text[] = {0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34}; // FIPS test vector
  unsigned char key[] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c}; // FIPS key
  unsigned char cryptoRef[] = {0x39,0x25,0x84,0x1d,0x02,0xdc,0x09,0xfb,0xdc,0x11,0x85,0x97,0x19,0x6a,0x0b,0x32};

  unsigned char original[16];
  strncpy((char *)original,(const char *)text,16);

  AES128 aes(key);
  aes.encrypt(text);
  if ( strncmp((const char *)text,(const char *)cryptoRef,16)!=0 )
    return 1;

  aes.decrypt(text);
  if ( strncmp((const char *)original,(const char *)text,16)!=0 )
    return 2;
    
  return 0;
}

/**
 *  AES-128 ECB test
 *
 *  This test uses test vectors from Appendix F of the NIST 800-38A (2001) document
 */
int AES_ECB_Test()
{
  unsigned char text[] = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
                          0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
                          0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
                          0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10};
  unsigned char key[] =  {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
  unsigned char cryptoRef[] = {0x3a,0xd7,0x7b,0xb4,0x0d,0x7a,0x36,0x60,0xa8,0x9e,0xca,0xf3,0x24,0x66,0xef,0x97,
                               0xf5,0xd3,0xd5,0x85,0x03,0xb9,0x69,0x9d,0xe7,0x85,0x89,0x5a,0x96,0xfd,0xba,0xaf,
                               0x43,0xb1,0xcd,0x7f,0x59,0x8e,0xce,0x23,0x88,0x1b,0x00,0xe3,0xed,0x03,0x06,0x88,
                               0x7b,0x0c,0x78,0x5e,0x27,0xe8,0xad,0x3f,0x82,0x23,0x20,0x71,0x04,0x72,0x5d,0xd4};

  unsigned char original[64];
  strncpy((char *)original,(const char *)text,64);

  ECBMode ecbaes(atAES128,key);
  ecbaes.encrypt(text,64);
  if ( strncmp((const char *)text,(const char *)cryptoRef,64)!=0 )
    return 1;

  ecbaes.decrypt(text,64);
  if ( strncmp((const char *)original,(const char *)text,64)!=0 )
    return 2;
    
  return 0;
}

/**
 *  AES-128 CBC test
 *
 *  This test uses test vectors from Appendix F of the NIST 800-38A (2001) document
 */

int AES_CBC_Test()
{
  unsigned char text[] = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
                          0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
                          0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
                          0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10};
  unsigned char key[] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
  unsigned char IV[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
  unsigned char cryptoRef[] = {0x76,0x49,0xab,0xac,0x81,0x19,0xb2,0x46,0xce,0xe9,0x8e,0x9b,0x12,0xe9,0x19,0x7d,
                               0x50,0x86,0xcb,0x9b,0x50,0x72,0x19,0xee,0x95,0xdb,0x11,0x3a,0x91,0x76,0x78,0xb2,
                               0x73,0xbe,0xd6,0xb8,0xe3,0xc1,0x74,0x3b,0x71,0x16,0xe6,0x9e,0x22,0x22,0x95,0x16,
                               0x3f,0xf1,0xca,0xa1,0x68,0x1f,0xac,0x09,0x12,0x0e,0xca,0x30,0x75,0x86,0xe1,0xa7};

  unsigned char original[64];
  strncpy((char *)original,(const char *)text,64);

  CBCMode cbcaes(atAES128,key);
  cbcaes.encrypt(text,64,IV);
  if ( strncmp((const char *)text,(const char *)cryptoRef,64)!=0 )
    return 1;
    
  cbcaes.decrypt(text,64,IV);
  if ( strncmp((const char *)original,(const char *)text,64)!=0 )
    return 2;
  
  return 0;
}

/**
 *  XTEA test
 *
 *  Official XTEA test vectors are hard to find.
 *  Can perhaps use http://www.freemedialibrary.com/index.php/XTEA_test_vectors but at the moment we
 *  let suffice that encrypted and decrypted texts match.
 */
int XTEA_Test()
{
  unsigned char key[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
  unsigned char text[] = {0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48};

  unsigned char original[8];
  strncpy((char *)original,(const char *)text,8);

  XTEA xtea(key);
  xtea.encrypt(text);
  xtea.decrypt(text);
  if ( strncmp((const char *)original,(const char *)text,8)!=0 )
    return 1;

  return 0;
}

/**
 *  Test of XTEA in ECB mode. 
 */
int XTEA_ECB_Test()
{
  unsigned char key[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
  unsigned char text[] = {0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,
                          0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,
                          0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,
                          0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48};
  unsigned char original[32];
  strncpy((char *)original,(const char *)text,32);

  ECBMode ecbxtea(atXTEA,key);
  ecbxtea.encrypt(text,32);
  ecbxtea.decrypt(text,32);
  if ( strncmp((const char *)original,(const char *)text,8)!=0 )
    return 1;

  return 0;
}

/**
 *  Test of XTEA in CBC mode
 */
int XTEA_CBC_Test()
{
  unsigned char key[] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
  unsigned char text[] = {0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,
                          0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,
                          0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,
                          0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48};
  unsigned char IV[] = {0x0,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
  unsigned char original[32];
  strncpy((char *)original,(const char *)text,32);

  CBCMode cbcxtea(atXTEA,key);
  cbcxtea.encrypt(text,32,IV);
  cbcxtea.decrypt(text,32,IV);
  if ( strncmp((const char *)original,(const char *)text,8)!=0 )
    return 1;
    
  return 0;
}

/**
 *  Test of AES128 CMAC. Use tests from RFC4494
 */
int AES128_CMAC_RFC4494_TEST()
{
  unsigned char CMAC0[] =
    {0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28,
     0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46};
  unsigned char CMAC16[] =
    {0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
     0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c};
  unsigned char CMAC40[] =
    {0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30,
     0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27};
  unsigned char CMAC64[] =
    {0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92,
     0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe};

  unsigned char K[] =
    {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
     0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};

  unsigned char M[] =
    {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
     0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
     0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
     0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
     0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
     0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
     0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
     0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};

  unsigned char CMAC[] =
    {0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
     0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0};

  AES128_CMAC cmac(K);

  cmac.mac(M,0,CMAC);
  if ( strncmp((const char *)CMAC, (const char *)CMAC0, 16)!=0 )
    return 1;

  cmac.mac(M,16,CMAC);
  if ( strncmp((const char *)CMAC, (const char *)CMAC16, 16)!=0 )
    return 2;

  cmac.mac(M,40,CMAC);
  if ( strncmp((const char *)CMAC, (const char *)CMAC40, 16)!=0 )
    return 3;

  cmac.mac(M,64,CMAC);
  if ( strncmp((const char *)CMAC, (const char *)CMAC64, 16)!=0 )
    return 4;

  // This is expected to pass 
  if ( !cmac.verify(M, 64, CMAC) )
    return 5;
  
  // This is expected to fail
  if ( cmac.verify(M, 64, CMAC40) )
    return 6;

  return 0;
}

/**
 *  Test of Encrypt-then-MAC authenticating encryption.
 *  This is a composition of encryption using AES-128 and CMAC using AES128-CMAC.
 *  See Bellare & Namprempre (2007)
 */ 
int AES_CMAC_EtM_Test()
{
  // This is the FIPS test vector
  unsigned char text[] = {0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34};
  unsigned char key[] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
  unsigned char IV[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
  unsigned char cryptoRef[] = {0x39,0x25,0x84,0x1d,0x02,0xdc,0x09,0xfb,0xdc,0x11,0x85,0x97,0x19,0x6a,0x0b,0x32};

  unsigned char original[16];
  strncpy((char *)original,(const char *)text,16);

  unsigned char buf[16+16]; // Make a buffer for the message with 16 bytes extra for the tag
  memcpy(buf,text,16);

  AES128CBC_CMAC_EtM etm(key,key); // Note: same key used here for encryption and 
                                   // MAC which is usually not a good cryptogrphic practice
  etm.encryptAndTag(buf,16,IV);
  if ( strncmp((const char *)buf,(const char *)cryptoRef,16)!=0 )
    return 1;

  // Verification should of course pass
  if ( !etm.verify(buf,16) )
    return 2;

  if ( !etm.decryptAndVerify(buf,16,IV) )
    return 3;

  if ( strncmp((const char *)original,(const char *)buf,16)!=0 )
    return 4;

  return 0;
}
