from cffi import FFI
import os
import platform
from typing import Any

ffi = FFI()
ffi.cdef('''
typedef enum {
    Success = 0,
    InvalidRootKey = 1,
    InvalidDerivationScheme = 2,
    InvalidLanguageCode = 3,
    InvalidUtf8 = 4
} ReturnCode;

ReturnCode derive_path(
    const uint8_t *root_xprv,
    const uint32_t *path,
    size_t path_length,
    uint8_t scheme,
    uint8_t *derived_xprv_out
);

ReturnCode key_gen(
    const uint8_t *root_xprv,
    uint32_t context,
    uint32_t account,
    uint32_t key_index,
    uint8_t scheme,
    uint8_t *derived_xprv_out
);

ReturnCode raw_sign(
    const uint8_t *root_xprv,
    const uint32_t *bip44_path,
    size_t path_length,
    const uint8_t *data,
    size_t data_length,
    uint8_t scheme,
    uint8_t *signature_out
);

ReturnCode sign(
    const uint8_t *root_xprv,
    uint32_t context,
    uint32_t account,
    uint32_t key_index,
    const uint8_t *data,
    size_t data_length,
    uint8_t scheme,
    uint8_t *signature_out
);

void from_seed(
    const uint8_t *seed,
    uint8_t *root_xprv_out
);

ReturnCode seed_from_mnemonic(
    const uint8_t *mnemonic,
    size_t mnemonic_length,
    uint8_t *seed_out,
    const uint8_t *lang_code,
    size_t lang_code_length,
    const uint8_t *passphrase,
    size_t passphrase_length
);
''')

# Determine library extension based on platform
_system = platform.system()
if _system == "Darwin":
    _lib_ext = ".dylib"
elif _system == "Linux":
    _lib_ext = ".so"
elif _system == "Windows":
    _lib_ext = ".dll"
else:
    raise RuntimeError(f"Unsupported platform: {_system}")

# Load library from the package directory
_dylib_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f'libed25519_bip32{_lib_ext}'
)
lib = ffi.dlopen(_dylib_path)

XPRV_SIZE = 96
XPUB_SIZE = 64
SIGNATURE_SIZE = 64
SEED_SIZE = 64

class DerivationScheme:
    V2 = 0
    Peikert = 1

class KeyContext:
    Address = 0
    Identity = 1

class ReturnCode:
    Success = 0
    InvalidRootKey = 1
    InvalidDerivationScheme = 2
    InvalidLanguageCode = 3
    InvalidUtf8 = 4

def _check_return_code(code: int) -> None:
    if code == ReturnCode.Success:
        return
    elif code == ReturnCode.InvalidRootKey:
        raise ValueError("Invalid root key")
    elif code == ReturnCode.InvalidDerivationScheme:
        raise ValueError("Invalid derivation scheme")
    elif code == ReturnCode.InvalidLanguageCode:
        raise ValueError("Invalid language code or mnemonic")
    elif code == ReturnCode.InvalidUtf8:
        raise ValueError("Invalid UTF-8 encoding")
    else:
        raise RuntimeError(f"Unknown return code: {code}")

def _to_u8_ptr(data: bytes) -> Any:
    return ffi.from_buffer(data)

def _to_u32_array(path: list[int]) -> Any:
    return ffi.new("uint32_t[]", path)

def _allocate_buffer(size: int) -> Any:
    return ffi.new(f"uint8_t[{size}]")

def _buffer_to_bytes(buffer: Any, size: int) -> bytes:
    return bytes(ffi.buffer(buffer, size))

def derive_path(root_xprv: bytes, path: list[int], scheme: int) -> bytes:
    if len(root_xprv) != XPRV_SIZE:
        raise ValueError(f"root_xprv must be {XPRV_SIZE} bytes")
    
    root_xprv_ptr = _to_u8_ptr(root_xprv)
    path_ptr = _to_u32_array(path)
    derived_xprv_out = _allocate_buffer(XPRV_SIZE)
   
    return_code = lib.derive_path(
        root_xprv_ptr,
        path_ptr,
        len(path),
        scheme,
        derived_xprv_out
    )
    
    _check_return_code(return_code)
    return _buffer_to_bytes(derived_xprv_out, XPRV_SIZE)

def key_gen(root_xprv: bytes, context: int, account: int, key_index: int, scheme: int) -> bytes:
    if len(root_xprv) != XPRV_SIZE:
        raise ValueError(f"root_xprv must be {XPRV_SIZE} bytes")
    
    root_xprv_ptr = _to_u8_ptr(root_xprv)
    derived_xprv_out = _allocate_buffer(XPRV_SIZE)
    
    return_code = lib.key_gen(
        root_xprv_ptr,
        context,
        account,
        key_index,
        scheme,
        derived_xprv_out
    )
    
    _check_return_code(return_code)
    return _buffer_to_bytes(derived_xprv_out, XPRV_SIZE)

def raw_sign(root_xprv: bytes, bip44_path: list[int], data: bytes, scheme: int) -> bytes:
    if len(root_xprv) != XPRV_SIZE:
        raise ValueError(f"root_xprv must be {XPRV_SIZE} bytes")
    
    root_xprv_ptr = _to_u8_ptr(root_xprv)
    path_ptr = _to_u32_array(bip44_path)
    data_ptr = _to_u8_ptr(data)
    signature_out = _allocate_buffer(SIGNATURE_SIZE)
    
    return_code = lib.raw_sign(
        root_xprv_ptr,
        path_ptr,
        len(bip44_path),
        data_ptr,
        len(data),
        scheme,
        signature_out
    )
    
    _check_return_code(return_code)
    return _buffer_to_bytes(signature_out, SIGNATURE_SIZE)

def sign(root_xprv: bytes, context: int, account: int, key_index: int, data: bytes, scheme: int) -> bytes:
    if len(root_xprv) != XPRV_SIZE:
        raise ValueError(f"root_xprv must be {XPRV_SIZE} bytes")
    
    root_xprv_ptr = _to_u8_ptr(root_xprv)
    data_ptr = _to_u8_ptr(data)
    signature_out = _allocate_buffer(SIGNATURE_SIZE)
    
    return_code = lib.sign(
        root_xprv_ptr,
        context,
        account,
        key_index,
        data_ptr,
        len(data),
        scheme,
        signature_out
    )
    
    _check_return_code(return_code)
    return _buffer_to_bytes(signature_out, SIGNATURE_SIZE)

def from_seed(seed: bytes) -> bytes:
    if len(seed) != SEED_SIZE:
        raise ValueError(f"seed must be {SEED_SIZE} bytes")
    
    seed_ptr = _to_u8_ptr(seed)
    root_xprv_out = _allocate_buffer(XPRV_SIZE)
    
    lib.from_seed(seed_ptr, root_xprv_out)
    
    return _buffer_to_bytes(root_xprv_out, XPRV_SIZE)

def seed_from_mnemonic(mnemonic: str, lang_code: str = "en", passphrase: str = "") -> bytes:
    mnemonic_bytes = mnemonic.encode('utf-8')
    lang_code_bytes = lang_code.encode('utf-8')
    passphrase_bytes = passphrase.encode('utf-8')
    
    mnemonic_ptr = _to_u8_ptr(mnemonic_bytes)
    lang_code_ptr = _to_u8_ptr(lang_code_bytes)
    passphrase_ptr = _to_u8_ptr(passphrase_bytes) if passphrase else ffi.NULL
    passphrase_len = len(passphrase_bytes) if passphrase else 0
    
    seed_out = _allocate_buffer(SEED_SIZE)
    
    return_code = lib.seed_from_mnemonic(
        mnemonic_ptr,
        len(mnemonic_bytes),
        seed_out,
        lang_code_ptr,
        len(lang_code_bytes),
        passphrase_ptr,
        passphrase_len
    )
    
    _check_return_code(return_code)
    return _buffer_to_bytes(seed_out, SEED_SIZE)

__all__ = [
    'ffi', 'lib',
    'derive_path', 'key_gen', 'raw_sign', 'sign',
    'from_seed', 'seed_from_mnemonic',
    'DerivationScheme', 'KeyContext', 'ReturnCode',
    'XPRV_SIZE', 'XPUB_SIZE', 'SIGNATURE_SIZE', 'SEED_SIZE'
]
