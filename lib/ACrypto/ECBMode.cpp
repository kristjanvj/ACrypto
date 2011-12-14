
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

#include "ECBMode.h"

ECBMode::ECBMode(AlgorithmType algorithmType, unsigned char *key)
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

ECBMode::~ECBMode()
{
	delete m_algorithm;
}

void ECBMode::encrypt(unsigned char *message, unsigned int length)
{
	int padlen = padMessage(message,length,m_algorithm->blocklength(),ptZero);
	int blocks = padlen / m_algorithm->blocklength();
	for ( int i=0; i<blocks; ++i )
		m_algorithm->encrypt(message+(i*m_algorithm->blocklength()));
}

void ECBMode::decrypt(unsigned char *message, unsigned int length)
{
	// The length should be a multiple of block length
	if ( length % m_algorithm->blocklength() != 0 )
		return;

	int blocks = length / m_algorithm->blocklength();
	for ( int i=0; i<blocks; ++i )
		m_algorithm->decrypt(message+(i*m_algorithm->blocklength()));
}



