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

#ifndef __ACRYPTO_HEADERS_H
#define __ACRYPTO_HEADERS_H

// Block ciphers
#include "AES128.h"
#include "XTEA.h"
// Modes of encryption
#include "ECBMode.h"
#include "CBCMode.h"
// MACs
#include "AES128_CMAC.h"
// Compositions
#include "AES128CBC_CMAC_EtM.h"

#endif /* __ACRYPTO_HEADERS_H */
