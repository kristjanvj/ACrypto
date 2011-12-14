
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

#ifndef __ACRYPTO_CBCMODE_H
#define __ACRYPTO_CBCMODE_H

#include "CryptoModeBase.h"
#include "BlockCipherAlgorithm.h"
#include "AES128.h"
#include "XTEA.h"

/**
 *  CBC-mode encryption and decryption. Works with any block cipher implementation which
 *  derives from BlockCipherBase. CryptoModeBase defines common utility functions such as
 *  padding.
 *
 *  @author Kristjan V. Jonsson (kristjanvj@gmail.com)
 *  @author Benedikt Kristinsson
 */
class CBCMode : public CryptoModeBase
{
	public:
		/**
         *  Constructor. Instantiate a block cipher algorithm with the given key. See
         *  CryptoDefs.h for details.
         */
		CBCMode(AlgorithmType algorithmType, unsigned char *key);
		virtual ~CBCMode();

	public:
		/**
         *  Encrypt a message stored in the buffer message. The message buffer MUST be of a
         *  size which is a multiple of the cipher block length. However, the length parameter
         *  should be the exact number of bytes in the plaintext itself, not the buffer size.
         *  The message is padded as necessary and encrypted. The ciphertext is returned
         *  in the message buffer.
         */
		virtual void encrypt(unsigned char *message, unsigned int length, unsigned char *IV);
		/**
         *  Decrypt a message. The buffer is assumed to be of a size which is an multiple of the
         *  cipher block length. The decrypted (plaintext) message is returned with padding
         *  intact in the message buffer.
         */
		virtual void decrypt(unsigned char *message, unsigned int length, unsigned char *IV);
		/**
         *  Refresh the key for the block cipher algorithm.
         */
		virtual void rekey(unsigned char *key);
};

#endif /* __ACRYPTO_CBCMODE_H */
