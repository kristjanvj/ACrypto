
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

#ifndef __ACRYPTO_XTEA_H
#define __ACRYPTO_XTEA_H

#include <string.h>
#include "BlockCipherAlgorithm.h"

#define XTEA_KEY_BYTES 16
#define XTEA_BLOCK_BYTES 8
#define XTEA_DEFAULT_NUM_ROUNDS 32

/**
 *  XTEA block cipher implementation.
 *
 *  Based on the reference implementation given on the wikipedia page and in the paper by XXXX.
 *
 *  @author Kristjan V. Jonsson (kristjanvj@gmail.com)
 */
class XTEA : public BlockCipherAlgorithm
{
	public:
		XTEA(unsigned char *key, int numRounds=XTEA_DEFAULT_NUM_ROUNDS);

	public:
		void rekey(unsigned char *key);

		static void encrypt(unsigned char *key, unsigned char *block, unsigned short rounds=XTEA_DEFAULT_NUM_ROUNDS);
		static void decrypt(unsigned char *key, unsigned char *block, unsigned short rounds=XTEA_DEFAULT_NUM_ROUNDS);

		virtual void encrypt(unsigned char *block);
		virtual void decrypt(unsigned char *block);

		virtual int keylength() {return  XTEA_KEY_BYTES;}
		virtual int blocklength() {return XTEA_BLOCK_BYTES;}

	private:
		int m_numRounds;
		unsigned char m_key[XTEA_KEY_BYTES];
};

#endif /* __ACRYPTO_XTEA_H */
