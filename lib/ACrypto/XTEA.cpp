
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

#include "XTEA.h"

XTEA::XTEA(unsigned char *key, int numRounds)
{
	m_numRounds = numRounds;
	rekey(key);
}

void XTEA::rekey(unsigned char *key)
{
	memcpy(m_key,key,XTEA_KEY_BYTES);
}

void XTEA::encrypt(unsigned char *key, unsigned char *block, unsigned short rounds)
{
    unsigned long y; //= (unsigned long)block;
    unsigned long z; // = (unsigned long)(block+4);
    unsigned long sum=0;
    unsigned long delta=0x9E3779B9;
    memcpy((unsigned char *)&y,block,4);
    memcpy((unsigned char *)&z,block+4,4);
    for (unsigned int i=0; i < rounds; i++)
	{
        y += (((z << 4) ^ (z >> 5)) + z) ^ (sum + key[sum & 3]);
        sum += delta;
        z += (((y << 4) ^ (y >> 5)) + y) ^ (sum + key[(sum>>11) & 3]);
    }
    memcpy(block,(unsigned char *)&y,4);
    memcpy(block+4,(unsigned char *)&z,4);
}

void XTEA::decrypt(unsigned char *key, unsigned char *block, unsigned short rounds)
{
    unsigned long y; // = (unsigned long)block;
    unsigned long z; // = (unsigned long)(block+4);
    unsigned long delta=0x9E3779B9;
    unsigned long sum = delta * rounds;
    memcpy((unsigned char *)&y,block,4);
    memcpy((unsigned char *)&z,block+4,4);
    for (unsigned int i=0; i < rounds; i++)
	{
        z -= (((y << 4) ^ (y >> 5)) + y) ^ (sum + key[(sum>>11) & 3]);
        sum -= delta;
        y -= (((z << 4) ^ (z >> 5)) + z) ^ (sum + key[sum & 3]);
    }
    memcpy(block,(unsigned char *)&y,4);
    memcpy(block+4,(unsigned char *)&z,4);
}

void XTEA::encrypt(unsigned char *block)
{
	encrypt(m_key,block,m_numRounds);
}

void XTEA::decrypt(unsigned char *block)
{
	decrypt(m_key,block,m_numRounds);
}

