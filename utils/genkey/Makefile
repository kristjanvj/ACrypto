CC = g++
CFLAGS =
LFLAGS = 

CRYPT_DIR = ../../aes_crypt/lib/
PROT_DIR =

IFLAGS = -I/usr/include/ -I$(CRYPT_DIR)

RM = /bin/rm

GENKEY_CC =	$(CC) -D_$(ARCH) $(IFLAGS) genkey.cpp \
			$(CRYPT_DIR)aes_crypt.cpp \
			$(CRYPT_DIR)aes_utils.cpp \
			-o generatekey

ARCH = 

genkey_i32: ARCH=INTEL_32
genkey_i32:
	$(GENKEY_CC)

genkey_i64: ARCH=INTEL_64
genkey_i64:
	$(GENKEY_CC)

clean:
	$(RM) generatekey
