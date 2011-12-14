
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

#ifndef __ACRYPTO_CRYPTO_MODE_BASE_H
#define __ACRYPTO_CRYPTO_MODE_BASE_H

#include <stdlib.h>
#include <string.h>
#include "BlockCipherAlgorithm.h"
#include "CryptoDefs.h"

/**
 *  Base class for crypto mode implementations. See for example CBCMode.
 *
 *  @author Kristjan V. Jonsson (kristjanvj@gmail.com)
 */
class CryptoModeBase
{
	protected:
		int padMessage(unsigned char *message, unsigned int length, unsigned int blocklen, PaddingType type=ptZero);

	private:
		int zeroPadding(unsigned char *message, unsigned int length, unsigned int blocklen);
		int oneZerosPadding(unsigned char *message, unsigned int length, unsigned int blocklen);

	protected:
		bool m_bDebug;
		AlgorithmType m_algorithmType;
		BlockCipherAlgorithm *m_algorithm;
};

#endif /* __ACRYPTO_CRYPTO_MODE_BASE_H */
