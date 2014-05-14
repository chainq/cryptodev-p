{* This is a source compatible implementation with the original API of
 * cryptodev by Angelos D. Keromytis, found at openbsd cryptodev.h.
 * Placed under public domain *}

{* Pascal conversion 2013.09.25 by Karoly Balogh <karoly.balogh@viprinet.com>
 * based on: https://github.com/nmav/cryptodev-linux/blob/master/crypto/cryptodev.h *}

{$IFDEF FPC}
{$MODE DELPHI}
{$PACKRECORDS C}
{$ENDIF}
unit cryptodev;

interface

{* CryptoDev headers changed IDs for CIOCASYNCCRYPT and CIOCASYNCFETCH 
 * which means the /dev/crypto binary interface is changed:
 * https://github.com/nmav/cryptodev-linux/commit/2770937dba40f6e96d5cf7c5ab1b2385c4c24057
 * Disable this define to use the new CryptoDev ABI *}
{.$DEFINE USE_OLD_CRYPTODEV_ABI}

uses
  ctypes;

{* API extensions for linux * }
const
 CRYPTO_HMAC_MAX_KEY_LEN   = 512;
 CRYPTO_CIPHER_MAX_KEY_LEN = 64;

{* All the supported algorithms
 *}
const
  CRYPTO_DES_CBC = 1;
  CRYPTO_3DES_CBC = 2;
  CRYPTO_BLF_CBC = 3;
  CRYPTO_CAST_CBC = 4;
  CRYPTO_SKIPJACK_CBC = 5;
  CRYPTO_MD5_HMAC = 6;
  CRYPTO_SHA1_HMAC = 7;
  CRYPTO_RIPEMD160_HMAC = 8;
  CRYPTO_MD5_KPDK = 9;
  CRYPTO_SHA1_KPDK = 10;
  CRYPTO_RIJNDAEL128_CBC = 11;
  CRYPTO_AES_CBC = CRYPTO_RIJNDAEL128_CBC;
  CRYPTO_ARC4 = 12;
  CRYPTO_MD5 = 13;
  CRYPTO_SHA1 = 14;
  CRYPTO_DEFLATE_COMP = 15;
  CRYPTO_NULL = 16;
  CRYPTO_LZS_COMP = 17;
  CRYPTO_SHA2_256_HMAC = 18;
  CRYPTO_SHA2_384_HMAC = 19;
  CRYPTO_SHA2_512_HMAC = 20;
  CRYPTO_AES_CTR = 21;
  CRYPTO_AES_XTS = 22;
  CRYPTO_AES_ECB = 23;
  CRYPTO_AES_GCM = 50;

  CRYPTO_CAMELLIA_CBC = 101;
  CRYPTO_RIPEMD160 = 102;
  CRYPTO_SHA2_224 = 103;
  CRYPTO_SHA2_256 = 104;
  CRYPTO_SHA2_384 = 105;
  CRYPTO_SHA2_512 = 106;
  CRYPTO_SHA2_224_HMAC = 107;
  CRYPTO_ALGORITHM_ALL = 108; {* Keep updated - see below *}

const
  CRYPTO_ALGORITHM_MAX = CRYPTO_ALGORITHM_ALL - 1;

{* Values for ciphers *}
const
  DES_BLOCK_LEN         = 8;
  DES3_BLOCK_LEN        = 8;
  RIJNDAEL128_BLOCK_LEN = 16;
  AES_BLOCK_LEN         = RIJNDAEL128_BLOCK_LEN;
  CAMELLIA_BLOCK_LEN    = 16;
  BLOWFISH_BLOCK_LEN    = 8;
  SKIPJACK_BLOCK_LEN    = 8;
  CAST128_BLOCK_LEN     = 8;

{* the maximum of the above *}
const
  EALG_MAX_BLOCK_LEN = 16;

{* Values for hashes/MAC *}
const
  AALG_MAX_RESULT_LEN = 64;

{* maximum length of verbose alg names (depends on CRYPTO_MAX_ALG_NAME) *}
const
  CRYPTODEV_MAX_ALG_NAME = 64;

const
  HASH_MAX_LEN = 64;

{* input of CIOCGSESSION *}
type
  TSessionOp = record
    {* Specify either cipher or mac
     *}
    cipher: cuint32;            {* cryptodev_crypto_op_t *}
    mac: cuint32;               {* cryptodev_crypto_op_t *}

    keylen: cuint32;
    key: pcuint8;
    mackeylen: cuint32;
    mackey: pcuint8;

    ses: cuint32;               {* session identifier *}
  end;
  PSessionOp = ^TSessionOp;

  TAlgInfo = record
    cra_name: array[1..CRYPTODEV_MAX_ALG_NAME] of char;
    cra_driver_name: array[1..CRYPTODEV_MAX_ALG_NAME] of char;
  end;

  TSessionInfoOp = record
    ses: cuint32;               {* session identifier *}

    {* verbose names for the requested ciphers *}
    cipher_info: TAlgInfo;
    hash_info: TAlgInfo;

    alignmask: cuint16;         {* alignment constraints *}
    flags: cuint32;             {* SIOP_FLAGS_* *}
  end;
  PSessionInfoOp = ^TSessionInfoOp;

{* If this flag is set then this algorithm uses
 * a driver only available in kernel (software drivers,
 * or drivers based on instruction sets do not set this flag).
 *
 * If multiple algorithms are involved (as in AEAD case), then
 * if one of them is kernel-driver-only this flag will be set.
 *}
const
  SIOP_FLAG_KERNEL_DRIVER_ONLY = 1;

const
  COP_ENCRYPT = 0;
  COP_DECRYPT = 1;

{* input of CIOCCRYPT *}
type
  TCryptOp = record
    ses: cuint32;               {* session identifier *}
    op: cuint16;                {* COP_ENCRYPT or COP_DECRYPT *}
    flags: cuint16;             {* see COP_FLAG_* *}
    len: cuint32;               {* length of source data *}
    src: pcuint8;               {* source data *}
    dst: pcuint8;               {* pointer to output data *}
    {* pointer to output data for hash/MAC operations *}
    mac: pcuint8;
    {* initialization vector for encryption operations *}
    iv: pcuint8;
  end;
  PCryptOp = ^TCryptOp;

{* input of CIOCAUTHCRYPT *}
  TCryptAuthOp = record
    ses: cuint32;               {* session identifier *}
    op: cuint16;                {* COP_ENCRYPT or COP_DECRYPT *}
    flags: cuint16;             {* see COP_FLAG_* *}
    len: cuint32;               {* length of source data *}
    auth_len: cuint32;          {* length of auth data *}
    auth_src: pcuint8;          {* authenticated-only data *}

    {* The current implementation is more efficient if data are
     * encrypted in-place (src==dst). *}
    src: pcuint8;               {* data to be encrypted and authenticated *}
    dst: pcuint8;               {* pointer to output data. Must have
                                 * space for tag. For TLS this should be at least 
                                 * len + tag_size + block_size for padding *}

    tag: pcuint8;               {* where the tag will be copied to. TLS mode
                                 * doesn't use that as tag is copied to dst.
                                 * SRTP mode copies tag there. *}
    tag_len: cuint32;           {* the length of the tag. Use zero for digest size or max tag. *}

    {* initialization vector for encryption operations *}
    iv: pcuint8;
    iv_len: cuint32;
  end;
  PCryptAuthOp = ^TCryptAuthOp;

{* In plain AEAD mode the following are required:
 *  flags   : 0
 *  iv      : the initialization vector (12 bytes)
 *  auth_len: the length of the data to be authenticated
 *  auth_src: the data to be authenticated
 *  len     : length of data to be encrypted
 *  src     : the data to be encrypted
 *  dst     : space to hold encrypted data. It must have
 *            at least a size of len + tag_size.
 *  tag_size: the size of the desired authentication tag or zero to use
 *            the maximum tag output.
 *
 * Note tag isn't being used because the Linux AEAD interface
 * copies the tag just after data.
 *}

{* In TLS mode (used for CBC ciphers that required padding) 
 * the following are required:
 *  flags   : COP_FLAG_AEAD_TLS_TYPE
 *  iv      : the initialization vector
 *  auth_len: the length of the data to be authenticated only
 *  len     : length of data to be encrypted
 *  auth_src: the data to be authenticated
 *  src     : the data to be encrypted
 *  dst     : space to hold encrypted data (preferably in-place). It must have
 *            at least a size of len + tag_size + blocksize.
 *  tag_size: the size of the desired authentication tag or zero to use
 *            the default mac output.
 *
 * Note that the padding used is the minimum padding.
 *}

{* In SRTP mode the following are required:
 *  flags   : COP_FLAG_AEAD_SRTP_TYPE
 *  iv      : the initialization vector
 *  auth_len: the length of the data to be authenticated. This must
 *            include the SRTP header + SRTP payload (data to be encrypted) + rest
 *
 *  len     : length of data to be encrypted
 *  auth_src: pointer the data to be authenticated. Should point at the same buffer as src.
 *  src     : pointer to the data to be encrypted.
 *  dst     : This is mandatory to be the same as src (in-place only).
 *  tag_size: the size of the desired authentication tag or zero to use
 *            the default mac output.
 *  tag     : Pointer to an address where the authentication tag will be copied.
 *}


{* struct crypt_op flags *}
const
  COP_FLAG_NONE           = (0 shl 0);    {* totally no flag *}
  COP_FLAG_UPDATE         = (1 shl 0);    {* multi-update hash mode *}
  COP_FLAG_FINAL          = (1 shl 1);    {* multi-update final hash mode *}
  COP_FLAG_WRITE_IV       = (1 shl 2);    {* update the IV during operation *}
  COP_FLAG_NO_ZC          = (1 shl 3);    {* do not zero-copy *}
  COP_FLAG_AEAD_TLS_TYPE  = (1 shl 4);    {* authenticate and encrypt using the 
                                           * TLS protocol rules *}
  COP_FLAG_AEAD_SRTP_TYPE = (1 shl 5);    {* authenticate and encrypt using the
                                           * SRTP protocol rules *}
  COP_FLAG_RESET          = (1 shl 6);    {* multi-update reset the state
                                           * should be used in combination
                                           * with COP_FLAG_UPDATE *}


{* Stuff for bignum arithmetic and public key
 * cryptography - not supported yet by linux
 * cryptodev.
 *}
const
  CRYPTO_ALG_FLAG_SUPPORTED  = 1;
  CRYPTO_ALG_FLAG_RNG_ENABLE = 2;
  CRYPTO_ALG_FLAG_DSA_SHA    = 4;

type
  TCrParam = record
    crp_p: pcuint8;
    crp_nbits: cuint32;
  end;

const
  CRK_MAXPARAM = 8;

{* input of CIOCKEY *}
type
  TCryptKOp = record
    crk_op: cuint32;           {* cryptodev_crk_op_t *}
    crk_status: cuint32;
    crk_iparams: cuint16;
    crk_oparams: cuint16;
    crk_pad1: cuint32;
    crk_param: array[0..CRK_MAXPARAM-1] of TCrParam;
  end;

const
  CRK_MOD_EXP = 0;
  CRK_MOD_EXP_CRT = 1;
  CRK_DSA_SIGN = 2;
  CRK_DSA_VERIFY = 3;
  CRK_DH_COMPUTE_KEY = 4;
  CRK_ALGORITHM_ALL = 5;

const
  CRK_ALGORITHM_MAX = (CRK_ALGORITHM_ALL-1);

{* features to be queried with CIOCASYMFEAT ioctl
 *}
const
  CRF_MOD_EXP         = (1 shl CRK_MOD_EXP);
  CRF_MOD_EXP_CRT     = (1 shl CRK_MOD_EXP_CRT);
  CRF_DSA_SIGN        = (1 shl CRK_DSA_SIGN);
  CRF_DSA_VERIFY      = (1 shl CRK_DSA_VERIFY);
  CRF_DH_COMPUTE_KEY  = (1 shl CRK_DH_COMPUTE_KEY);


{* ioctl's. Compatible with old linux cryptodev.h
 *}
var
  CRIOGET,                  { _IOWR('c', 101, __u32) }
  CIOCGSESSION,             { _IOWR('c', 102, struct session_op) }
  CIOCFSESSION,             { _IOW('c', 103, __u32) }
  CIOCCRYPT,                { _IOWR('c', 104, struct crypt_op) }
  CIOCKEY,                  { _IOWR('c', 105, struct crypt_kop) }
  CIOCASYMFEAT,             { _IOR('c', 106, __u32) }
  CIOCGSESSINFO: cuint32;   { _IOWR('c', 107, struct session_info_op) }

{* to indicate that CRIOGET is not required in linux
 *}
const
  CRIOGET_NOT_NEEDED = 1;

{* additional ioctls for AEAD *}
var
  CIOCAUTHCRYPT: cuint32;   { _IOWR('c', 109, struct crypt_auth_op) }

{* additional ioctls for asynchronous operation.
 * These are conditionally enabled since version 1.6.
 *}
var
  CIOCASYNCCRYPT,           { _IOW('c', 110, struct crypt_op) }
  CIOCASYNCFETCH: cuint32;  { _IOR('c', 111, struct crypt_op) }

implementation

uses
  linuxioctl;

const
  CryptoType: Byte = Ord('c');

initialization
  CRIOGET        := _IOWR(CryptoType, 101, sizeof(cuint32));
  CIOCGSESSION   := _IOWR(CryptoType, 102, sizeof(TSessionOp));
  CIOCFSESSION   := _IOW(CryptoType, 103, sizeof(cuint32));
  CIOCCRYPT      := _IOWR(CryptoType, 104, sizeof(TCryptOp));
  CIOCKEY        := _IOWR(CryptoType, 105, sizeof(TCryptKOp));
  CIOCASYMFEAT   := _IOR(CryptoType, 106, sizeof(cuint32));
  CIOCGSESSINFO  := _IOWR(CryptoType, 107, sizeof(TSessionInfoOp));

  CIOCAUTHCRYPT  := _IOWR(CryptoType, 109, sizeof(TCryptAuthOp));

{$IFDEF USE_OLD_CRYPTODEV_ABI}
  CIOCASYNCCRYPT := _IOW(CryptoType, 107, sizeof(TCryptOp));
  CIOCASYNCFETCH := _IOR(CryptoType, 108, sizeof(TCryptOp));
{$ELSE}
  CIOCASYNCCRYPT := _IOW(CryptoType, 110, sizeof(TCryptOp));
  CIOCASYNCFETCH := _IOR(CryptoType, 111, sizeof(TCryptOp));
{$ENDIF}
end. {* unit cryptodev *}
