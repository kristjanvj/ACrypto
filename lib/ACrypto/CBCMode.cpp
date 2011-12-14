
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

#include "CBCMode.h"

CBCMode::CBCMode(AlgorithmType algorithmType, unsigned char *key)
{
	m_algorithmType=algorithmType;

	switch(m_algorithmType)
	{
		case atAES128:
			m_algorithm = new AES128(key);
			break;
		case atXTEA:
			m_algorithm = new XTEA(key);
			break;
	}
}

CBCMode::~CBCMode()
{
	delete m_algorithm;
}

void CBCMode::encrypt(unsigned char *message, unsigned int length, unsigned char *IV)
{
	int blocklength = m_algorithm->blocklength();
	int padlen = padMessage(message,length,blocklength,ptZero);
	int blocks = padlen / blocklength;

	//unsigned char *pCipherBytes = (unsigned char *)message;

	// CBC encrypt:  C_i = E_k(P_i XOR C_{i-1})
	for (int i = 0; i < blocks; i++)
	{
		for (int bb=0; bb<blocklength; bb++)
		{
			if ( i==0 )
				message[bb] ^= IV[bb]; // First block needs the IV
			else
				message[bb+(i*blocklength)] ^= message[bb+(i*blocklength)-blocklength];
		}

		m_algorithm->encrypt(message+(i*blocklength));
	}
}

void CBCMode::decrypt(unsigned char *message, unsigned int length, unsigned char *IV)
{
    int blocklength = m_algorithm->blocklength();
    int blocks = length / blocklength;

	unsigned char ccur[blocklength];
	unsigned char cprev[blocklength];

    memcpy(cprev,IV,blocklength);
	for ( int i=0; i<blocks; i++ )
	{
	    memcpy(ccur,message+(i*blocklength),blocklength);
		m_algorithm->decrypt(message+(i*blocklength));
		for(int bb=0; bb<blocklength; bb++)
			message[bb+(i*blocklength)] ^= cprev[bb];
		memcpy(cprev,ccur,blocklength);
	}
}

void CBCMode::rekey(unsigned char *key)
{
	m_algorithm->rekey(key);
}


