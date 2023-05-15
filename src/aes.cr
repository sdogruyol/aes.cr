require "openssl/lib_crypto"
 
lib LibCrypto
  EVP_MAX_BLOCK_LENGTH = 32
 
  type EvpMd = Void*
  type EvpCipher = Void*
  type Engine = Void*
 
  alias EvpCipherCtx = Void
 
  fun evp_decrypt_final_ex = EVP_DecryptFinal_ex(ctx : EvpCipherCtx*, outm : UInt8*, outl : LibC::Int*) : LibC::Int
  fun evp_decrypt_update = EVP_DecryptUpdate(ctx : EvpCipherCtx*, out : UInt8*, outl : LibC::Int*, in : UInt8*, inl : LibC::Int) : LibC::Int
  fun evp_encrypt_final_ex = EVP_EncryptFinal_ex(ctx : EvpCipherCtx*, out : UInt8*, outl : LibC::Int*) : LibC::Int
  fun evp_encrypt_update = EVP_EncryptUpdate(ctx : EvpCipherCtx*, out : UInt8*, outl : LibC::Int*, in : UInt8*, inl : LibC::Int) : LibC::Int
  fun evp_decrypt_init_ex = EVP_DecryptInit_ex(ctx : EvpCipherCtx*, cipher : EvpCipher, impl : Void*, key : UInt8*, iv : UInt8*) : LibC::Int
  fun evp_encrypt_init_ex = EVP_EncryptInit_ex(ctx : EvpCipherCtx*, cipher : EvpCipher, impl : Void*, key : UInt8*, iv : UInt8*) : LibC::Int
  fun evp_aes_128_cbc = EVP_aes_128_cbc : EvpCipher
  fun evp_aes_192_cbc = EVP_aes_192_cbc : EvpCipher
  fun evp_aes_256_cbc = EVP_aes_256_cbc : EvpCipher
  fun evp_cipher_ctx_new = EVP_CIPHER_CTX_new : EvpCipherCtx*
  fun evp_cipher_ctx_free = EVP_CIPHER_CTX_free(ctx : EvpCipherCtx*)
  fun evp_cipher_ctx_init = EVP_CIPHER_CTX_reset(c : EvpCipherCtx*) : LibC::Int
  fun get_error = ERR_get_error : LibC::ULong
  fun get_error_string = ERR_error_string(code : LibC::ULong, buf : Pointer(LibC::Char)) : Pointer(Char)
end
 
class AES
  getter encrypt_context : LibCrypto::EvpCipherCtx* = LibCrypto.evp_cipher_ctx_new
  getter decrypt_context : LibCrypto::EvpCipherCtx* = LibCrypto.evp_cipher_ctx_new
  getter bits : Int32 = 256
  getter key : Slice(UInt8)
  getter iv : Slice(UInt8)
  property nonce_size : Int32 = 2
 
  SUPPORTED_BITSIZES = [128, 192, 256]
  READABLE_CHARS     = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ~!@#$%^&*()_+=-?/>.<,;:]}[{|".chars
  CHARS              = (0_u8..255_u8).to_a
 
  def finalize
    LibCrypto.evp_cipher_ctx_free(encrypt_context)
    LibCrypto.evp_cipher_ctx_free(decrypt_context)
  end
  
  def self.generate_key(length = 32)
    key = ""
    length.times { key += CHARS.sample(Random::Secure).chr }
    key
  end
 
  def self.generate_key_readable(length = 32)
    key = ""
    length.times { key += READABLE_CHARS.sample(Random::Secure) }
    key
  end
 
  def initialize
    initialize(AES.generate_key_readable(32), AES.generate_key_readable(32), 256)
  end
 
  def initialize(bits : Int32 = 256)
    keysize = bits == 256 ? 32 : 16
    initialize(AES.generate_key_readable(keysize), AES.generate_key_readable(keysize), bits)
  end
 
  def initialize(key : String, iv : String, bits : Int32 = 256)
    initialize(key.to_slice, iv.to_slice, bits)
  end
 
  def initialize(key : Slice(UInt8), iv : Slice(UInt8), bits : Int32 = 256)
    LibCrypto.evp_cipher_ctx_init(@encrypt_context)
    LibCrypto.evp_cipher_ctx_init(@decrypt_context)
    case bits
    when 128
      LibCrypto.evp_encrypt_init_ex(@encrypt_context, LibCrypto.evp_aes_128_cbc, nil, key, iv)
      LibCrypto.evp_decrypt_init_ex(@decrypt_context, LibCrypto.evp_aes_128_cbc, nil, key, iv)
    when 192
      LibCrypto.evp_encrypt_init_ex(@encrypt_context, LibCrypto.evp_aes_192_cbc, nil, key, iv)
      LibCrypto.evp_decrypt_init_ex(@decrypt_context, LibCrypto.evp_aes_192_cbc, nil, key, iv)
    when 256
      LibCrypto.evp_encrypt_init_ex(@encrypt_context, LibCrypto.evp_aes_256_cbc, nil, key, iv)
      LibCrypto.evp_decrypt_init_ex(@decrypt_context, LibCrypto.evp_aes_256_cbc, nil, key, iv)
    else
      raise "bits must be one of #{SUPPORTED_BITSIZES}"
    end
    @bits = bits
    @key = key
    @iv = iv
  end
 
  def encrypt(data : Slice(UInt8))
    tmp = Slice.new(data.size + nonce_size, 0u8)
    data.copy_to(tmp)
    data = tmp
    nonce_size.times { |i| data[data.size - i - 1] = CHARS.sample(Random::Secure) }
    c_len = data.size + LibCrypto::EVP_MAX_BLOCK_LENGTH
    f_len = 0
    ciphertext = Slice.new(c_len, 0u8)
    if LibCrypto.evp_encrypt_init_ex(@encrypt_context, nil, nil, nil, nil) != 1
      raise_ssl_error("evp_encrypt_init")
    end
    if LibCrypto.evp_encrypt_update(@encrypt_context, ciphertext.to_unsafe, pointerof(c_len), data, data.size) != 1
      raise_ssl_error("evp_encrypt_update")
    end
    if LibCrypto.evp_encrypt_final_ex(@encrypt_context, ciphertext.to_unsafe + c_len, pointerof(f_len)) != 1
      raise_ssl_error("evp_encrypt_final")
    end
    ciphertext[0, f_len + c_len]
  end
 
  def encrypt(str : String)
    encrypt(str.to_slice)
  end
 
  def decrypt(data : Slice(UInt8))
    p_len = data.size
    len = data.size
    f_len = 0
    plaintext = Slice.new(p_len, 0u8)
    if LibCrypto.evp_decrypt_init_ex(@decrypt_context, nil, nil, nil, nil) != 1
      raise_ssl_error("evp_decrypt_init")
    end
    if LibCrypto.evp_decrypt_update(@decrypt_context, plaintext.to_unsafe, pointerof(p_len), data.to_unsafe, len) != 1
      raise_ssl_error("evp_decrypt_update")
    end
    if LibCrypto.evp_decrypt_final_ex(@decrypt_context, plaintext.to_unsafe + p_len, pointerof(f_len)) != 1
      raise_ssl_error("evp_decrypt_final")
    end
    plaintext[0, p_len + f_len - nonce_size]
  end
 
  def decrypt(str : String)
    decrypt(str.as_slice)
  end
 
  class Error < Exception
    getter call
    getter code
    getter reason
 
    def initialize(@call : String, @code : UInt64, @reason : String)
      super("OpenSSL returned an error: #{@reason} (function: #{call}, code: #{@code})")
    end
  end
 
  private def raise_ssl_error(func : String)
    code = LibCrypto.get_error
    reason = LibCrypto.get_error_string(code, nil)
    instance = Error.new(func, code, String.new(reason))
    raise instance
  end
end
 
class String
  def as_slice
    bts = bytes
    Slice.new(bts.to_unsafe, bts.size)
  end
end