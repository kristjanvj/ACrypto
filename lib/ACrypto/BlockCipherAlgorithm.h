
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

#ifndef __ACRYPTO_BLOCK_CIPHER_ALGORITHM_H
#define __ACRYPTO_BLOCK_CIPHER_ALGORITHM_H

#include <stdlib.h>
#include "CryptoDefs.h"

/**
 *  Abstract base class for a block cipher algorithm. All block cipher implementations should
 *  derive from this class.
 *
 *  @author Kristjan V. Jonsson (kristjanvj@gmail.com)
 */
class BlockCipherAlgorithm
{
	public:
		virtual void encrypt(unsigned char *message)=0;
		virtual void decrypt(unsigned char *message)=0;

		virtual void rekey(unsigned char *key)=0;

		virtual int keylength()=0;
		virtual int blocklength()=0;
};

#endif /* __ACRYPTO_BLOCK_CIPHER_ALGORITHM_H */
