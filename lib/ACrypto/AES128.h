
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

#ifndef __ACRYPTO_AES128_H
#define __ACRYPTO_AES128_H

#include <string.h>
#include "BlockCipherAlgorithm.h"

#define AES128_KEY_BYTES 16
#define AES128_BLOCK_BYTES 16
#define AES128_ROUNDS 10   // Nr

enum TableOptions {toHeader, toEEPROM, toProgmem};

/**
 *  ntransform -- normal transform macro to help with the loop unrolling
 */
#define ntransform(text,round) SubAndShift(text);MixColumns(text);AddRoundKey(text,round);
/**
 *  dtransform - help with the loop unrolling
 */
#define dtransform(cipher,round) InvSubAndShift(cipher);AddRoundKey(cipher,round);InvMixColumns(cipher);

/**
 *  @brief AES128 block cipher implementation
 *
 *  @author Kristjan V. Jonsson (kristjanvj@gmail.com)
 *  @author Kristjan Runarsson
 *  @author Benedikt Kristinsson
 */
class AES128 : public BlockCipherAlgorithm
{
	public:
		AES128(unsigned char *key, TableOptions tableOptions=toHeader);

	public:
		virtual void rekey(unsigned char *key);

		static void encrypt(unsigned char *key, unsigned char *block);
		static void decrypt(unsigned char *key, unsigned char *block);

		virtual void encrypt(unsigned char *block);
		virtual void decrypt(unsigned char *block);

		virtual int keylength() {return AES128_KEY_BYTES;}
		virtual int blocklength() {return AES128_BLOCK_BYTES;}

		void generateKeySchedule(const unsigned char *key, unsigned char *keys); // TODO: WHY PUBLIC??

	public:
		// Utilities
		void initLookupInEEPROM(int memsize, int sboxoffset, int isboxoffset, int rconoffset);
		void initLookupInProgmem();
		void writeLookupsToEEPROM(int memsize, int sboxoffset, int isboxoffset, int rconoffset);
//		void printBytes(unsigned char *pBytes, int dLength, int dLineLen=16);

	private:
		TableOptions m_tableOptions;
		unsigned char m_pKeys[AES128_KEY_BYTES*11];

		int m_eeprom_memSize;
		int m_sboxoffset;
		int m_isboxoffset;
		int m_rconoffset;

	private:
		// Key manipulation functions
		void KeyExpansion(const unsigned char *key, unsigned char *keys);
		void AddRoundKey(void *pText, int round);

		// Round functions
		void SubAndShift(void *pText);
		void MixColumns(void *pText);
		void InvSubAndShift(void *pText);
		void InvMixColumns(void *pText);

		// Accessors for lookup tables
		unsigned char getSboxValue(int index);
		unsigned char getISboxValue(int index);
		unsigned char getRconValue(int index);
};

#endif /* __ACRYPTO_AES128_H */
