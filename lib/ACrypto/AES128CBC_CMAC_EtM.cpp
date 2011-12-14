
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
 **********************************************************************************************
 */

#include "AES128CBC_CMAC_EtM.h"

AES128CBC_CMAC_EtM::AES128CBC_CMAC_EtM(unsigned char *KE, unsigned char *KM)
{
	aescbc=NULL;
	cmac=NULL;
	rekey(KE,KM);
}

AES128CBC_CMAC_EtM::~AES128CBC_CMAC_EtM()
{
	if (aescbc!=NULL)
		delete aescbc;
	if (cmac!=NULL)
		delete cmac;
}

void AES128CBC_CMAC_EtM::encryptAndTag(unsigned char *message, unsigned int length, unsigned char *IV)
{
	aescbc->encrypt(message,length,IV);
//	unsigned char tag[AES128_BLOCK_BYTES];
	cmac->mac(message,length-AES128_BLOCK_BYTES,message+length);
}

bool AES128CBC_CMAC_EtM::decryptAndVerify(unsigned char *message, unsigned int length, unsigned char *IV)
{
	if ( !verify(message,length) )
		return false;
	aescbc->decrypt(message,length,IV);
	return true;
}

bool AES128CBC_CMAC_EtM::verify(unsigned char *message, unsigned int length)
{
	unsigned char tag[AES128_BLOCK_BYTES];
	cmac->mac(message,length-AES128_BLOCK_BYTES,tag);
	return (strncmp((char *)tag,(char *)(message+length),AES128_BLOCK_BYTES)==0);
}

void AES128CBC_CMAC_EtM::rekey(unsigned char *KE, unsigned char *KM)
{
	if (aescbc!=NULL)
		delete aescbc;
	aescbc = new CBCMode(atAES128,KE);
	if (cmac!=NULL)
		delete cmac;
	cmac = new AES128_CMAC(KM);
}
