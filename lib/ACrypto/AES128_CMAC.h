
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

#ifndef __ACRYPTO_CMAC_H
#define __ACRYPTO_CMAC_H

#define CMAC_VALID 1
#define CMAC_INVALID 0

#include <math.h>
#include "AES128.h"

const unsigned char constRb[] =
    {0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
     0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x87};

/**
 *  @brief AES128-based CMAC
 *
 *  This CMAC uses the AES128 block cipher algorithm and derives from that class in this library.
 *
 *  @author Kristjan Runarsson
 *  @author Kristjan V. Jonsson (kristjanvj@gmail.com)
 */
class AES128_CMAC : public AES128
{
	public:
		AES128_CMAC(unsigned char *key) : AES128(key) {};

	public:
		virtual void mac(unsigned char *message, unsigned int mlen, unsigned char *tag);
		static void mac(unsigned char *key, unsigned char *message, unsigned int mlen, unsigned char *tag);
		virtual bool verify(unsigned char *message, unsigned int mlen, unsigned char *tag);
		static bool verify(unsigned char *key, unsigned char *message, unsigned int mlen, unsigned char *tag);

	protected:
		void leftShiftKey(unsigned char *orig, unsigned char *shifted);
		void xorToLength(unsigned char *p, unsigned char *q, unsigned char *r);
		void expandMacKey(unsigned char *origKey, unsigned char *newKey);
		void padding ( unsigned char *lastb, unsigned char *pad, unsigned long length);
		void aesCMac(unsigned char *M, unsigned long length, unsigned char *cmac);
		bool aesCMacVerify(unsigned char *M, unsigned int M_length, unsigned char * CMACm);
};

#endif /* __ACRYPTO_CMAC_H */
