
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

#ifndef __ACRYPTO_AES128CBC_CMAC_EtM_H
#define __ACRYPTO_AES128CBC_CMAC_EtM_H

#include "CBCMode.h"
#include "AES128_CMAC.h"

/**
 *  @brief Encrypt-then-MAC composition using AES128 and CMAC (AES128-based).
 *
 *  This is a simple demonstration of a composition of cryptographic primitives, specifically
 *  block cipher based encryption and MAC.
 *
 *  @author Kristjan V. Jonsson
 *  @author Kristjan Runarsson
 */
class AES128CBC_CMAC_EtM
{
	public:
        /**
         *  Constructor. Instantiates CBC mode AES and CMAC modules, each with a separate
         *  128-bit key.
         */
		AES128CBC_CMAC_EtM(unsigned char *KE, unsigned char *KM);
		virtual ~AES128CBC_CMAC_EtM();
	public:
		/**
         *  Encrypt and tag (MAC) a message using CBC mode AES128 encryption.
         *  The message buffer MUST be of a size which is a
         *  multiple of the cipher block length PLUS the size of the tag. The plaintext message
         *  is padded as needed, encrypted and written in the lower N-1 blocks of the message
         *  buffer. The tag is returned in the last message block.
         */
		void encryptAndTag(unsigned char *message, unsigned int length, unsigned char *IV);
		/**
         *  Decrypt and verify an encrypted and tagged message. The message buffer is assumed to
         *  be of a size which is a multiple of the cipher block length PLUS the size of the tag.
         *  The decrypted message (with padding intact) is returned in the lower N-1 blocks of
         *  the message buffer. The tag is NOT stripped off. The message is verified and the
         *  result returned. The decryption is not performed if the verification fails.
         */
		bool decryptAndVerify(unsigned char *message, unsigned int length, unsigned char *IV);
		/**
         *  Verify a tagged message. The message buffer is assumed to
         *  be of a size which is a multiple of the cipher block length PLUS the size of the tag.
         *  The function returns true if the tag is verified sucessfully.
         */
		bool verify(unsigned char *message, unsigned int length);
		/**
         *  Rekey the encryption and MAC algorithms. Distinct keys are assumed -- its generally a
         *  bad idea to re-use any cryptographic key for more than one purpose.
         */
		void rekey(unsigned char *KE, unsigned char *KM);
	private:
		CBCMode *aescbc;    /// The CBC mode AES encryption instance
		AES128_CMAC *cmac;  /// The CMAC instance
};

#endif /* __ACRYPTO_AES128CBC_CMAC_EtM_H */
