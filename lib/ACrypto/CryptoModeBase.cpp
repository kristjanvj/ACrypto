
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

#include "CryptoModeBase.h"

void* operator new(size_t size) { return malloc(size); }
void operator delete(void* ptr) { if (ptr) free(ptr); }

int CryptoModeBase::padMessage(unsigned char *message, unsigned int length, unsigned int blocklen, PaddingType type)
{
	switch(type)
	{
		case ptZero:
			return zeroPadding(message,length,blocklen);
		case ptOneZeros:
			return oneZerosPadding(message,length,blocklen);
		default:
			return zeroPadding(message,length,blocklen);
	}
}

int CryptoModeBase::zeroPadding(unsigned char *message, unsigned int length, unsigned int blocklen)
{
	if ( length % blocklen == 0 )
		return length;

	int dPadlen = blocklen - (length % blocklen);
	message = (unsigned char *)realloc(message,length+dPadlen);
	memset(message+length,0x00,dPadlen);

	return length+dPadlen;
}

int CryptoModeBase::oneZerosPadding(unsigned char *message, unsigned int length, unsigned int blocklen)
{
	int dPadlen;
	if ( length % blocklen == 0 )
		dPadlen=blocklen;
	else
		dPadlen = blocklen - (length % blocklen);

	message = (unsigned char *)realloc(message,length+dPadlen);
	memset(message+length,0x00,dPadlen);
	message[length]=0x80;

	return length+dPadlen;
}

