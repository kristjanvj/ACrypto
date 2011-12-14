
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

#include "AES128.h"
#include "aes_tables.h"

#define unroll_decrypt_loop
#define unroll_encrypt_loop

//
// The xtime macro is used in the mixColumns transformation. It implements the
// left shift and conditional XOR operations described in FIPS-197, section 4.2.1.
// This can be implemented by a procedure and a conditional statement, but the
// macro is a much more compact form.
//
// This macro is similar to one in the PolarSSL library
// http://www.polarssl.org/?page=show_source&file=aes.
// The twotimes and threetimes macros are based on the description by Daemen and Rijmen.
#define xtime(a)  (a<<1) ^ ((a & 0x80) ? 0x1b : 0x00)
// See the paper by Daemen and Rijmen (sec 2.1.3) on the 2x and 3x multiplication.
#define twotimes(a)  (((a<<1) ^ (((a>>7) & 1) * 0x1b)) & 0xFF)
#define threetimes(a) (a^twotimes(a))
#define four(a) twotimes(twotimes(a))
#define eight(a) twotimes(four(a))
#define sixteen(a) four(four(a))

// byte rotate left and right
#define brl(w,n) ( ( w << (8*n) | w >> (32-8*n) ) & 0xFFFFFFFF )
#define brr(w,n) ( ( w >> (8*n) | w << (32-8*n) ) & 0xFFFFFFFF )

// Access an element i,j from a linear char array, indexed for convenience as the AES state.
#define state(p,i,j) (p[i+4*j])

AES128::AES128(unsigned char *key, TableOptions tableOptions)
{
	rekey(key);
	m_tableOptions = tableOptions;
}

void AES128::rekey(unsigned char *key)
{
	KeyExpansion(key,m_pKeys);
}

//static
void AES128::encrypt(unsigned char *key, unsigned char *block)
{
	//
}

//static
void AES128::decrypt(unsigned char *key, unsigned char *block)
{
	//
}

/**
 *  encrypt
 *
 *  Encrypt a single block, stored in the buffer text. The buffer MUST be 16
 *  bytes in length!
 *  pKeys stores a complete key schedule for the round.
 *  The algorithm, call order and function names, follows the reference of
 *  FIPS-197, section 5.1.
 *
 *  The encryption loop can be unrolled or left as is by using the
 *  unroll_encrypt_loop define.
 *
 *  The encrypted data is returned in the text buffer.
 *
 *  Note: Only 10 rounds and 128 bit keys are supported in this implementation.
 */
void AES128::encrypt(unsigned char *block)
{
    // XOR the first key to the first state
	AddRoundKey(block, 0);

    #if defined(unroll_encrypt_loop)
    ntransform(block, 1);
    ntransform(block, 2);
    ntransform(block, 3);
    ntransform(block, 4);
    ntransform(block, 5);
    ntransform(block, 6);
    ntransform(block, 7);
    ntransform(block, 8);
    ntransform(block, 9);
    #else
	int round;
	for (round=1; round<AES128_ROUNDS; ++round)
	{
		SubAndShift(block);
		MixColumns(block);
		AddRoundKey(block, round);
	}
    #endif

	// Now, do the final round of encryption
	SubAndShift(block);
	AddRoundKey(block, AES128_ROUNDS);  // add the last round key from the schedule
}

/**
 *  decrypt
 *
 *  Decrypt a single block, stored in the buffer, take a pointer to the buffer.
 *  The buffer _MUST_ be 16 bytes in length!
 *  pKeys stores a complete key schedule for the round.
 *
 * Follows the references of FIPS-197, Section 5.3 (Inverse Cipher)
 */
void AES128::decrypt(unsigned char *block)
{
  // XOR the first key to the first state.
  AddRoundKey(block, AES128_ROUNDS);

  #if defined(unroll_decrypt_loop)
  dtransform(block, 9);
  dtransform(block, 8);
  dtransform(block, 7);
  dtransform(block, 6);
  dtransform(block, 5);
  dtransform(block, 4);
  dtransform(block, 3);
  dtransform(block, 2);
  dtransform(block, 1);
  #else
  int round;
  for(round=AES128_ROUNDS-1; round>0; round--)
  {
    InvSubAndShift(block);
    AddRoundKey(block, round);
    InvMixColumns(block);
  }
  #endif

  // The last round is different (Round 0) -- there is no MixColumns.
  InvSubAndShift(block);
  AddRoundKey(block, 0);
}

void AES128::initLookupInEEPROM(int memsize, int sboxoffset, int isboxoffset, int rconoffset)
{
	m_eeprom_memSize = memsize;
	m_sboxoffset = sboxoffset;
	m_isboxoffset = isboxoffset;
	m_rconoffset = rconoffset;
}

void AES128::initLookupInProgmem()
{
	//
}

void AES128::writeLookupsToEEPROM(int memsize, int sboxoffset, int isboxoffset, int rconoffset)
{
	//
}

void AES128::generateKeySchedule(const unsigned char *key, unsigned char *keys)
{
	KeyExpansion(key,keys); // TODO: VALIDATE SIZE OF KEYS
}

/* ----------------------------------------------------------------------------------------------
 * Private member functions
 * ---------------------------------------------------------------------------------------------- */

/**
 *  KeyExpansion()
 *
 *  Implements the AES key expansion algorithm.
 *  Note: only supports 128 bit keys and 10 rounds.
 *  See FIPS-197 and http://en.wikipedia.org/wiki/Rijndael_key_schedule on the algorithm.
 *  The Rcon table used in the algorithm copied from (but not verified!) the wikipedia
 *  article.
 *  key is the ecryption key, whereas keys are the derived expansion keys.
 */
void AES128::KeyExpansion(const unsigned char *key, unsigned char *keys)
{
	memcpy(keys,key,AES128_KEY_BYTES); // Copy the first key

	int r=1; // The Rcon counter
	for(int i=16; i<176; i+=4)
	{
		// The SubWord and RotWord methods described in Section 5.2 of FIPS-197 are
        // replaced here by their inlined equivalents. The algorithm is also simplifyed
        // by not supporting the longer key lengths. Several steps are combined to be
        // able to compute keys in-place without temporary variables.
        if (i % 16 == 0)  // Dividable by 16, the first key
		{
			// Copy the previous four bytes with rotate.
			// Apply the AES Sbox to the four bytes of the key only.
			// Multiply the first byte with the Rcon.
			keys[i] = keys[i-16] ^ getSboxValue(keys[i-3]) ^ getRconValue(r++);
			keys[i+1] = keys[i-15] ^ getSboxValue(keys[i-2]);
			keys[i+2] = keys[i-14] ^ getSboxValue(keys[i-1]);
			keys[i+3] = keys[i-13] ^ getSboxValue(keys[i-4]);
		}
		else
		{
			// Straight copy and rotate of the previous key bytes.
			keys[i] = keys[i-16] ^ keys[i-4];
			keys[i+1] = keys[i-15] ^ keys[i-3];
			keys[i+2] = keys[i-14] ^ keys[i-2];
			keys[i+3] = keys[i-13] ^ keys[i-1];
		}
	}
}

/**
 *  AddRoundKey
 *
 *  Adds a key from the schedule (for the specified round) to the current state.
 *  Loop unrolled for a bit of performance gain
 *  The key is XOR-ed to the state
 */
void AES128::AddRoundKey(void *pText, int round)
{
	int roundOffset=round*4;
	unsigned long *pState = (unsigned long *)pText;
	unsigned long *pKeys = (unsigned long *)m_pKeys;

	pState[0] ^= pKeys[roundOffset];
	pState[1] ^= pKeys[roundOffset+1];
	pState[2] ^= pKeys[roundOffset+2];
	pState[3] ^= pKeys[roundOffset+3];
}

/**
 *  SubAndShift
 *
 *  Implementation of the AES subBytes and shiftRows operations.
 *
 *  The AES sbox is applied to each byte as the shift is performed
 *  Loop unrolled for a bit of preformance gain.
 *
 *  See: FIPS-197.
 *  See: http://en.wikipedia.org/wiki/Rijndael_S-box
 */
void AES128::SubAndShift(void *pText)
{
	unsigned char *pState = (unsigned char*)pText;
	unsigned char temp;

	// Only sbox for first row
	state(pState,0,0) = getSboxValue(state(pState,0,0));
	state(pState,0,1) = getSboxValue(state(pState,0,1));
	state(pState,0,2) = getSboxValue(state(pState,0,2));
	state(pState,0,3) = getSboxValue(state(pState,0,3));
	// Shift and sbox the second row
	temp=state(pState,1,0);
	state(pState,1,0)=getSboxValue(state(pState,1,1));
	state(pState,1,1)=getSboxValue(state(pState,1,2));
	state(pState,1,2)=getSboxValue(state(pState,1,3));
	state(pState,1,3)=getSboxValue(temp);
	// Shift and sbox the third row
	temp = state(pState,2,0);
	state(pState,2,0)=getSboxValue(state(pState,2,2));
	state(pState,2,2)=getSboxValue(temp);
	temp = state(pState,2,1);
	state(pState,2,1)=getSboxValue(state(pState,2,3));
	state(pState,2,3)=getSboxValue(temp);
	// Shift and sbox the fourth row
	temp = state(pState,3,3);
	state(pState,3,3) = getSboxValue(state(pState,3,2));
	state(pState,3,2) = getSboxValue(state(pState,3,1));
	state(pState,3,1) = getSboxValue(state(pState,3,0));
	state(pState,3,0) = getSboxValue(temp);
} // SubAndShift

// InvSubAndShift()
//
// Implements the inverse of the AES operations SubBytes and ShiftRows.
// Applies the inverted SBox to the bytes while and shifts the
// rows backwards.
void AES128::InvSubAndShift(void *pText)
{
	unsigned char *pState = (unsigned char*)pText;
	unsigned char temp;

	// Loop unrolled for a bit of performance gain

	// The first row isnt rotataed, only isboxed
	state(pState,0,0) = getISboxValue(state(pState,0,0));
	state(pState,0,1) = getISboxValue(state(pState,0,1));
	state(pState,0,2) = getISboxValue(state(pState,0,2));
	state(pState,0,3) = getISboxValue(state(pState,0,3));
	// Second row is shifted one byte to the left
	temp = state(pState,1,3);
	state(pState,1,3) = getISboxValue(state(pState,1,2));
	state(pState,1,2) = getISboxValue(state(pState,1,1));
	state(pState,1,1) = getISboxValue(state(pState,1,0));
	state(pState,1,0) = getISboxValue(temp);
	// Third row is shifted two bytes to the left
	temp = state(pState,2,2);
	state(pState,2,2) = getISboxValue(state(pState,2,0));
	state(pState,2,0) = getISboxValue(temp);
	temp = state(pState,2,1);
	state(pState,2,1) = getISboxValue(state(pState,2,3));
	state(pState,2,3) = getISboxValue(temp);
	// The fourth row is shifted three bytes to the left
	temp = state(pState,3,0);
	state(pState,3,0) = getISboxValue(state(pState,3,1));
	state(pState,3,1) = getISboxValue(state(pState,3,2));
	state(pState,3,2) = getISboxValue(state(pState,3,3));
	state(pState,3,3) = getISboxValue(temp);
} // InvSubAndShift()


/**
 *  MixColumns
 *
 * The MixColumns function is the trickiest to implement efficiently since it
 * contains a lot of expensive operations if implemented literally as stated
 * in FIPS-197.
 *
 * Considerable experimentation, trial, error and literature search lead to
 * the present form. A fuller discussion and the sources used are cited in the
 * body of the function.
 *
 */
void AES128::MixColumns(void *pText)
{
	// The sub bytes operation is as follows (see 5.1.3 in the FIPS-197 document):
	//
	// s'_0,c = ({02} * s_0,c ) XOR ({03} * s_1,c ) XOR s_2,c XOR s_3,c
	// s'_1,c = s_0,c XOR ({02} * s_1,c ) XOR ({03} * s_2,c ) XOR s_3,c
	// s'_2,c = s_0,c XOR s_1,c XOR ({02} * s_2,c ) XOR ({03} * s_3,c )  ′
	// s'_3,c = ({03} * s_0,c ) XOR s_1,c XOR s_2,c XOR ({02} * s_3,c )
	//
	// The * operation is here multiplication in the AES (Rijndael) finite field. See section
	// 4.2.1 in FIPS-197 on the multiplication and the xtime function.
	// A much clearer description can be found in
	//           http://www.usenix.org/event/cardis02/full_papers/valverde/valverde_html/node12.html
	//
	// The xtime function is as follows:
	// xtime(a) = a<<1 if x7==0 (the eight bit is 0)
	// xtime(a) = a<<1 XOR Ox1 if x7==1

	// see also:
	// * http://en.wikipedia.org/wiki/Rijndael_mix_columns
	// * http://en.wikipedia.org/wiki/Rijndael_Galois_field
	// * http://www.usenix.org/event/cardis02/full_papers/valverde/valverde_html/node12.html

	unsigned char *pState = (unsigned char *)pText;
	unsigned char a, s0;

	int c;
	for(c = 0; c < 4; c++)
	{
		// This algorithm is adapted from the paper
		// "Efficient AES Implementations for ARM Based Platforms" by Atasu, Breveglieri and Macchetti (2004)
		// Note: This is in essence identical to the code from Daemen and Rijmen (sec. 5.1).
		//
		// temp[0] = xtime(pState[0][c] ^ pState[1][c]) ^ pState[1][c] ^ pState[2][c] ^ pState[3][c];
		// temp[1] = xtime(pState[1][c] ^ pState[2][c]) ^ pState[2][c] ^ pState[3][c] ^ pState[0][c];
		// temp[2] = xtime(pState[2][c] ^ pState[3][c]) ^ pState[3][c] ^ pState[0][c] ^ pState[1][c];
		// temp[3] = xtime(pstate[3][c] ^ pstate[0][c]) ^ pState[0][c] ^ pState[1][c] ^ pState[2][c];
		//
		// The code below is a variation of the pseudocode in the document by Daemen and Rijmen (sec. 5.1)
		// and allows us to dispense with the temporary variable: a single initial XOR A of all four
		// states is computed. Then, temporary variables can be avoided by XORing A with the xtime calculation
		// and the target field itself. This self-XOR nullifies the corresponding term from A, avoiding
		// the temporary variable. The use of the a variable also saves quite a few XORs.
		// This is reimplemented as follows:
		a = state(pState,0,c) ^ state(pState,1,c) ^ state(pState,2,c) ^ state(pState,3,c);
		s0 = state(pState,0,c); // This is the only temporary variable needed
		state(pState,0,c) ^= xtime((state(pState,0,c) ^ state(pState,1,c))) ^ a;
		state(pState,1,c) ^= xtime((state(pState,1,c) ^ state(pState,2,c))) ^ a;
		state(pState,2,c) ^= xtime((state(pState,2,c) ^ state(pState,3,c))) ^ a;
		state(pState,3,c) ^= xtime((state(pState,3,c) ^ s0)) ^ a;
		// Here, we need to use a temp, since the contents of s0c have been modified
	}
} // MixColumns()

/**
 *  InvMixColumns
 *
 *  See http://en.wikipedia.org/wiki/Rijndael_mix_columns
 */
void AES128::InvMixColumns(void *pText)
{
	unsigned char *pState = (unsigned char *)pText;
	unsigned char s0, s1, s2, s3;

	int c;
	for (c = 0; c < 4; c++)
	{
		s0 = state(pState,0,c); // S_0,0
		s1 = state(pState,1,c); // S_1,0
		s2 = state(pState,2,c); // S_2,0
		s3 = state(pState,3,c); // S_3,0

		// * is multiplication is GF(2^8)
		// s'_0,c = (0x0e * s0) xor (0x0b * s1) xor (0x0d * s2) xor (0x09 * s3)
		state(pState,0,c) = (eight(s0)^four(s0)^xtime(s0)) ^ (eight(s1)^xtime(s1)^s1) ^ (eight(s2)^four(s2)^s2) ^ (eight(s3) ^ s3);

		// s'_1,c = (0x09 * s0) xor (0x0e * s1) xor (0x0b * s2) xor (0x0d * s3)
		state(pState,1,c) = (eight(s0)^s0) ^ (eight(s1)^four(s1)^xtime(s1)) ^ (eight(s2)^xtime(s2)^s2) ^ (eight(s3)^four(s3)^s3);

		// s'_2,c = (0x0d * s0) xor (0x09 * s1) xor (0x0e * s2) xor (0x0b * s3)
		state(pState,2,c) = (eight(s0)^four(s0)^s0) ^ (eight(s1)^s1) ^ (eight(s2)^four(s2)^xtime(s2)) ^ (eight(s3)^xtime(s3)^s3);

		// s'_3,c = (0x0b * s0) xor (0x0d * s1) xor (0x09 * s2) xor (0x0e * s3)
		state(pState,3,c) = (eight(s0)^xtime(s0)^s0) ^ (eight(s1)^four(s1)^s1) ^ (eight(s2)^s2) ^ (eight(s3)^four(s3)^xtime(s3));
	}
} // InvMixColumns()

/**
 *  getSboxValue
 *
 *  Accessor for the SBOX lookup table. Arduino systems look into the EEPROM
 *  while other platforms use in-memory tables.
 */
unsigned char AES128::getSboxValue(int index)
{
/*	switch(m_tableOptions)
	{
		case toProgmem:
			return 0x00; // TODO: IMPLEMENT
		case toEEPROM:
			if( (m_sboxoffset+index) >= m_eeprom_memSize )
				return 0x00;
			return EEPROM.read(m_sboxoffset+index);
		case toHeader:
		default:
			return sbox[index];
	} */
	return sbox[index];
}

/**
 *  getISboxValue
 *
 *  Accessor for the ISBOX lookup table. Arduino systems look into the EEPROM
 *  while other platforms use in-memory tables.
 */
unsigned char AES128::getISboxValue(int index)
{
/*	switch(m_tableOptions)
	{
		case toProgmem:
			return 0x00; // TODO: IMPLEMENT
		case toEEPROM:
			if( (m_isboxoffset+index) >= m_eeprom_memSize )
				return 0x00;
			return EEPROM.read(m_isboxoffset+index);
		case toHeader:
		default:
			return isbox[index];
	} */
	return isbox[index];
}

/**
 *  getRconValue
 *
 *  Accessor for the Rcon lookup table. Arduino systems look into the EEPROM
 *  while other platforms use in-memory tables.
 */
unsigned char AES128::getRconValue(int index)
{
/*	switch(m_tableOptions)
	{
		case toProgmem:
			return 0x00; // TODO: IMPLEMENT
		case toEEPROM:
			if( (m_rconoffset+index) >= m_eeprom_memSize )
				return 0x00;
			return EEPROM.read(m_rconoffset+index);
		case toHeader:
		default:
			return Rcon[index];
	} */
	return Rcon[index];
}

