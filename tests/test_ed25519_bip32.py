from xhd_wallet_api_py import (
    derive_path,
    key_gen,
    raw_sign,
    sign,
    from_seed,
    seed_from_mnemonic,
    DerivationScheme,
    KeyContext,
    XPRV_SIZE,
    SEED_SIZE,
)

VALID_ROOT_KEY = bytes.fromhex(
    "f8a29231ee38d6c5bf715d5bac21c750577aa3798b22d79d65bf97d6fade"
    "a15adcd1ee1abdf78bd4be64731a12deb94d3671784112eb6f364b871851"
    "fd1c9a247384db9ad6003bbd08b3b1ddc0d07a597293ff85e961bf252b33"
    "1262eddfad0d"
)

ROOT_KEY_HEX = (
    "a8ba80028922d9fcfa055c78aede55b5c575bcd8d5a53168edf45f36d9ec8f469"
    "4592b4bc892907583e22669ecdf1b0409a9f3bd5549f2dd751b51360909cd05796"
    "b9206ec30e142e94b790a98805bf999042b55046963174ee6cee2d0375946"
)

BIP44_PATH = [0x8000002c, 0x8000011b, 0x80000000, 0, 0]

def test_derive_path_success():
    derived = derive_path(VALID_ROOT_KEY, BIP44_PATH, DerivationScheme.Peikert)
    assert len(derived) == XPRV_SIZE
    assert derived != VALID_ROOT_KEY

def test_derive_path_invalid_root_key():
    invalid_root_key = bytes(XPRV_SIZE)
    try:
        derive_path(invalid_root_key, BIP44_PATH, DerivationScheme.Peikert)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Invalid root key" in str(e)

def test_derive_path_invalid_scheme():
    try:
        derive_path(VALID_ROOT_KEY, BIP44_PATH, 99)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Invalid derivation scheme" in str(e)

def test_key_gen_address():
    derived = key_gen(VALID_ROOT_KEY, KeyContext.Address, 0, 0, DerivationScheme.Peikert)
    assert len(derived) == XPRV_SIZE

def test_key_gen_identity():
    derived = key_gen(VALID_ROOT_KEY, KeyContext.Identity, 0, 0, DerivationScheme.Peikert)
    assert len(derived) == XPRV_SIZE

def test_key_gen_invalid_root_key():
    invalid_root_key = bytes(XPRV_SIZE)
    try:
        key_gen(invalid_root_key, KeyContext.Address, 0, 0, DerivationScheme.Peikert)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Invalid root key" in str(e)

def test_key_gen_invalid_context():
    try:
        key_gen(VALID_ROOT_KEY, 99, 0, 0, DerivationScheme.Peikert)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Invalid derivation scheme" in str(e)

def test_key_gen_invalid_scheme():
    try:
        key_gen(VALID_ROOT_KEY, KeyContext.Address, 0, 0, 99)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Invalid derivation scheme" in str(e)

def test_raw_sign():
    root_key = bytes.fromhex(ROOT_KEY_HEX)
    data = b"Hello World"
    signature = raw_sign(root_key, BIP44_PATH, data, DerivationScheme.Peikert)
    assert len(signature) == 64

def test_raw_sign_invalid_root_key():
    invalid_root_key = bytes(XPRV_SIZE)
    data = b"Hello World"
    try:
        raw_sign(invalid_root_key, BIP44_PATH, data, DerivationScheme.Peikert)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Invalid root key" in str(e)

def test_raw_sign_invalid_scheme():
    root_key = bytes.fromhex(ROOT_KEY_HEX)
    data = b"Hello World"
    try:
        raw_sign(root_key, BIP44_PATH, data, 99)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Invalid derivation scheme" in str(e)

def test_sign():
    root_key = bytes.fromhex(ROOT_KEY_HEX)
    data = b"Hello World"
    signature = sign(root_key, KeyContext.Address, 0, 0, data, DerivationScheme.Peikert)
    assert len(signature) == 64

def test_sign_invalid_root_key():
    invalid_root_key = bytes(XPRV_SIZE)
    data = b"Hello World"
    try:
        sign(invalid_root_key, KeyContext.Address, 0, 0, data, DerivationScheme.Peikert)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Invalid root key" in str(e)

def test_sign_invalid_context():
    root_key = bytes.fromhex(ROOT_KEY_HEX)
    data = b"Hello World"
    try:
        sign(root_key, 99, 0, 0, data, DerivationScheme.Peikert)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Invalid derivation scheme" in str(e)

def test_sign_invalid_scheme():
    root_key = bytes.fromhex(ROOT_KEY_HEX)
    data = b"Hello World"
    try:
        sign(root_key, KeyContext.Address, 0, 0, data, 99)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Invalid derivation scheme" in str(e)

MNEMONIC = "salon zoo engage submit smile frost later decide wing sight chaos renew lizard rely canal coral scene hobby scare step bus leaf tobacco slice"
SEED_HEX = "3aff2db416b895ec3cf9a4f8d1e970bc9819920e7bf44a5e350477af0ef557b1511b0986debf78dd38c7c520cd44ff7c7231618f958e21ef0250733a8c1915ea"

def test_seed_from_mnemonic_success():
    seed = seed_from_mnemonic(MNEMONIC, "en")
    assert len(seed) == SEED_SIZE
    assert seed == bytes.fromhex(SEED_HEX)

def test_seed_from_mnemonic_invalid_mnemonic():
    try:
        seed_from_mnemonic("invalid mnemonic words here", "en")
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Invalid language code or mnemonic" in str(e)

def test_seed_from_mnemonic_invalid_language():
    try:
        seed_from_mnemonic(MNEMONIC, "invalid")
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Invalid language code or mnemonic" in str(e)

def test_seed_from_mnemonic_with_passphrase():
    seed = seed_from_mnemonic(MNEMONIC, "en", "my passphrase")
    assert len(seed) == SEED_SIZE
    assert seed != bytes.fromhex(SEED_HEX)

def test_from_seed_success():
    seed = bytes.fromhex(SEED_HEX)
    root_xprv = from_seed(seed)
    assert len(root_xprv) == XPRV_SIZE
    assert root_xprv == bytes.fromhex(ROOT_KEY_HEX)

def test_from_seed_invalid_size():
    try:
        from_seed(bytes(32))
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "seed must be 64 bytes" in str(e)

def test_seed_to_xprv_roundtrip():
    seed = seed_from_mnemonic(MNEMONIC, "en")
    root_xprv = from_seed(seed)
    assert len(root_xprv) == XPRV_SIZE
    assert root_xprv == bytes.fromhex(ROOT_KEY_HEX)

def test_derive_from_seed_generated_key():
    seed = bytes.fromhex(SEED_HEX)
    root_xprv = from_seed(seed)
    derived = derive_path(root_xprv, BIP44_PATH, DerivationScheme.Peikert)
    assert len(derived) == XPRV_SIZE
    assert derived != root_xprv

def test_sign_from_seed_generated_key():
    seed = bytes.fromhex(SEED_HEX)
    root_xprv = from_seed(seed)
    data = b"Hello World"
    signature = sign(root_xprv, KeyContext.Address, 0, 0, data, DerivationScheme.Peikert)
    assert len(signature) == 64

