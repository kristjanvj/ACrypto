
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

#include "AES128_CMAC.h"

void AES128_CMAC::mac(unsigned char *message, unsigned int mlen, unsigned char *tag)
{
	aesCMac(message, mlen, tag);
}

//static
void AES128_CMAC::mac(unsigned char *key, unsigned char *message, unsigned int mlen, unsigned char *tag)
{
	// TODO: IMPLEMENT
}

//virtual
bool AES128_CMAC::verify(unsigned char *message, unsigned int mlen, unsigned char *tag)
{
    return aesCMacVerify(message, mlen, tag);
}

//static
bool AES128_CMAC::verify(unsigned char *key, unsigned char *message, unsigned int mlen, unsigned char *tag)
{
    //
    return false; // TODO: IMPLEMENT
}

// Left shifts every element of an array of length BLOCK_BYTE_SIZE. This
// is equivalent to left shifting the entire 128 bit binary string the array
// represents. The first bit of each left shifted element becomes the last
// bit of the preceeding one.
void AES128_CMAC::leftShiftKey(unsigned char *orig, unsigned char *shifted){
    unsigned char overFlow =  0x0;

    for(int i = AES128_BLOCK_BYTES - 1; i >= 0; i--){
        shifted[i] = (orig[i] << 1);
        shifted[i] = shifted[i] | overFlow;
        overFlow = (orig[i] & 0x80) ? 0x1 : 0x0;
    }
}

// Performs (p XOR q) on every element of an array of length BLOCK_BYTE_SIZE
// and copies the result into r.
void AES128_CMAC::xorToLength(unsigned char *p, unsigned char *q, unsigned char *r){
    unsigned long i;
    for(i = 0; i < AES128_BLOCK_BYTES; i++){
        r[i] = p[i] ^ q[i];
    }
}

/* A not quite literal implementation of the Generate_Subkey psuedocode
 * algorithm in section 2.4 of RFC 4493. This function expands a single
 * AES encryption key into one expanded key of the type of key needed
 * for MAC generation rather than two like the psuedo code in the RFC.
 * Call this twice to get K1 and K2.
 */
void AES128_CMAC::expandMacKey(unsigned char *origKey, unsigned char *newKey){
    leftShiftKey(origKey, newKey);
    // FIXME: Is there an endian issue here?
    if((origKey[0] & 0x80) != 0x0){
        xorToLength(newKey, (unsigned char*)constRb, newKey);
    }
}

// TODO: Use padding function from CryptoModeBase?
//
// Pads a message with a single '1' followed by the minimum number
// of '0' such that the string's total lenght is 128 bits.
void AES128_CMAC::padding ( unsigned char *lastb, unsigned char *pad, unsigned long length ) {
    unsigned long i;

    for (i=0; i<AES128_BLOCK_BYTES; i++) {
        if (i < length) {
            pad[i] = lastb[i];
        } else if (i == length) {
            pad[i] = 0x80;
        } else {
            pad[i] = 0x00;
        }
    }
}

/* This is a more or less literal implementation of the AES-CMAC psuedo
 * code algorithm in section 2.4 of RFC 4493.
 *
 * +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * +                   Algorithm AES-CMAC                              +
 * +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * +                                                                   +
 * +   Input    : KS        Rijandel key schedule                      +
 * +            : M,        Message that key will be generated from.   +
 * +            : M_length, Message length in bytes (len in the RFC)   +
 * +   Output   : CMAC,     The resulting cMAC authentication          +
 * +                        code (T in the RFC)                        +
 * +                                                                   +
 * +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 */
void AES128_CMAC::aesCMac(unsigned char *M, unsigned long M_length, unsigned char *CMAC)
{
    unsigned char K1[AES128_BLOCK_BYTES], K2[AES128_BLOCK_BYTES],
             L[AES128_BLOCK_BYTES], M_last[AES128_BLOCK_BYTES];

	memset(K1,0,AES128_BLOCK_BYTES);
	memset(K2,0,AES128_BLOCK_BYTES);
	memset(L,0,AES128_BLOCK_BYTES);
	memset(M_last,0,AES128_BLOCK_BYTES);

    unsigned long blockCount = 0;

    bool isComplete = true;

    // Step 1.
	encrypt(L);
    expandMacKey(L, K1);
    expandMacKey(K1, K2);

    // Step 2. determine the needed number of blocks of lenght BLOCK_BYTE_SIZE.
    blockCount = (unsigned long)ceil((double) M_length / (double)AES128_BLOCK_BYTES); // TODO: Can we get by w/o double calc?

    // Step 3. Check whether M needs padding or not.
    if(blockCount == 0){
        blockCount = 1;
        isComplete = false;
    } else {
        if ((M_length % AES128_BLOCK_BYTES) == 0) { // The last block needs no padding.
            isComplete = true;
        } else {
            isComplete = false;
        }
    }

    // Step 4. Handle messages depending whether they are an integer multiple
    // of BLOCK_BYTE_SIZE or not.
    unsigned char M_lastPad[AES128_BLOCK_BYTES];

    if (isComplete) { // the last block does not need padding.
        xorToLength(&M[AES128_BLOCK_BYTES * (blockCount - 1)], K1, M_last);
    } else { // No padding needed.
        memset(M_lastPad,0,AES128_BLOCK_BYTES);
        padding(&M[AES128_BLOCK_BYTES * (blockCount - 1)], M_lastPad,
                (M_length % AES128_BLOCK_BYTES));
        xorToLength(M_lastPad, K2, M_last);
    }

    // Step 5. Perfrom the CBC encryption chain up to (M_length - 1)
    unsigned char X[AES128_BLOCK_BYTES], Y[AES128_BLOCK_BYTES];
	memset(X,0,AES128_BLOCK_BYTES);
	memset(Y,0,AES128_BLOCK_BYTES);

    // Step 6.
    unsigned long i, j;
    for(i = 0; i < blockCount-1; i++){
        //Y := X XOR M_i;
        xorToLength(X, &M[AES128_BLOCK_BYTES * i], Y);
        //AES-128(K,Y);
		encrypt(Y);

        // X:= AES-128(K,Y); Necessary because encryptBlock does not copy the
        // encrypted text into a new target vector.
        for(j = 0; j < AES128_BLOCK_BYTES; j++){
            X[j] = Y[j];
        }
    }

    // XOR and encrypt the last block of M to produce the CMAC.
    xorToLength(X, M_last, Y);
	encrypt(Y);

    // Step 7. T := AES-128(K,Y); where in our case T == CMAC
    for(i = 0; i < AES128_BLOCK_BYTES; i++){
        CMAC[i] = Y[i];
    }
}

bool AES128_CMAC::aesCMacVerify(unsigned char *M, unsigned int M_length, unsigned char * CMACm)
{

	unsigned char CMAC[AES128_BLOCK_BYTES];

    mac(M, M_length, CMAC);

/*    int32_ard i;
    for(i = 0; i<BLOCK_BYTE_SIZE; i++){
        if(CMAC[i] != CMACm[i]){
            return 0;
        }
    }

    return 1; */

    // TODO: How about truncated MACs?
    return ( strncmp((const char *)CMAC, (const char *)CMACm, AES128_BLOCK_BYTES)==0 );
}
