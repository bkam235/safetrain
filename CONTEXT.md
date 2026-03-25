# safetrain — Project Context

## What it does

R package for **reversible, key-based anonymization** of tabular data. Given a data frame and a secret key, it produces an anonymized data frame. The transformation is exactly reversible with the correct key, but irreversible without it.

## Core algorithm (two methods, selectable via `opts$method`)

### PCA (default, `method = "pca"`)

1. **Encode** all selected columns to numeric (factors → integer codes, dates → epoch, etc.)
2. **Center & scale** using values derived from the key via HMAC-SHA256 (not stored)
3. **Rotate** using a key-derived orthogonal matrix (HMAC-PRNG → Gaussian matrix → QR decomposition; not stored)
4. **Drop** the last rotated column, encrypt it with XOR keystream, store in mapping
5. Output: `n-1` anonymized columns named `anon_1, ..., anon_{n-1}`

Reversal re-derives rotation/centering from key, decrypts the dropped column, inverts the rotation, and decodes back to original types. Recovery is exact within floating-point tolerance (~1e-8).

### Cryptoencoder (`method = "cryptoencoder"`)

1. **Encode** columns to numeric (same as PCA)
2. **Center & scale** using key-derived values (same as PCA)
3. **Normalize** data (data-derived center/scale, stored encrypted in mapping)
4. **Train** a shallow n→n autoencoder (1 hidden layer, tanh activation, no bottleneck) on the normalized data. Weights initialized deterministically from key via HMAC-PRNG + Xavier scaling. Adam optimizer trains to near-zero reconstruction loss.
5. **Encode** data through the trained encoder → n hidden activations (all in (-1,1) due to tanh)
6. **Encrypt** trained weights + normalization params with key-derived XOR stream, store in mapping
7. Output: `n` anonymized columns named `anon_1, ..., anon_n` (same column count as input)

Reversal decrypts the weights, applies the decoder network (`output = hidden %*% W_dec + b_dec`), and reverses both data normalization and key-derived center/scale. Recovery is exact within floating-point tolerance (~1e-4) because n→n has enough capacity for near-perfect reconstruction.

**Theoretical guarantees:**
- **No column correspondence**: every output column `h_j = tanh(Σ_k x_k·W_kj + b_j)` depends on ALL input columns via the trained full-rank weight matrix
- **No cell correspondence**: cell (i,j) in output is a nonlinear function of ALL cells in row i; without the key, encrypted weights cannot be recovered
- **Diffeomorphism**: with full-rank W_enc, the encoder is a smooth invertible map, preserving ML expressive power on anonymized data

## Package structure

```
R/
  anon.R        — anonymize_data(), deanonymize_data() (public API)
  key.R         — generate_key(), key_from_passphrase(), normalize_key(),
                  derive_column_key(), hmac_prng_stream()
  transform.R   — PCA rotation, cryptoencoder transforms,
                  encrypt/decrypt, encode/decode columns, crypto helpers
  data.R        — sample_data documentation
  zzz.R         — imports (stats::na.omit, stats::setNames)

tests/testthat/
  test-anonymize.R         — basic anonymization behavior
  test-reversibility.R     — round-trip accuracy for all column types
  test-key-functions.R     — key generation/derivation
  test-encode-decode.R     — column type encoding round-trips
  test-crypto-helpers.R    — orthogonal matrices, encryption, PRNG
  test-column-reduction.R  — output has fewer columns than input
  test-key-dependence.R    — wrong key ≠ original data, mapping insufficient
  test-cryptoencoder.R     — cryptoencoder unit/integration tests
  test-model-performance.R — ML performance preserved after round-trip

vignettes/
  ml-safe-anonymization.Rmd

data/           — sample_data.rda (1000 × 7)
data-raw/       — sample_data generation script
```

## Exported API

| Function | Purpose |
|---|---|
| `generate_key(bytes=32)` | Random 256-bit key (raw vector) |
| `key_from_passphrase(passphrase)` | Deterministic key from passphrase (SHA256) |
| `anonymize_data(data, key, columns=NULL, opts=list())` | Returns `list(data, mapping)`. `opts$method`: `"pca"` or `"cryptoencoder"` |
| `deanonymize_data(data_anon, key, mapping)` | Returns original data frame |

## Dependencies

- **Runtime**: `digest` (HMAC-SHA256)
- **Suggests**: `testthat`, `ranger`, `knitr`, `rmarkdown`
- **Base R only** for QR decomposition, matrix operations

## Security properties

- Rotation matrix (PCA): derived from key, never stored
- Center/scale: derived from key, never stored
- Dropped column (PCA): encrypted with key-derived XOR stream
- Trained weights (cryptoencoder): encrypted with key-derived XOR stream
- Mapping alone is insufficient for reversal

## Key design decisions

- Single-column anonymization: no column drop (degenerate case, PCA only)
- Cryptoencoder: n→n mapping, no information loss, works for n≥1
- Cross-platform portability: `endian = "little"` in writeBin/readBin
- Orthogonal matrix sign fixed via positive diag(R) in QR for determinism
- Cryptoencoder training: Adam optimizer with early stopping (loss < tol or max_epochs)
- Tolerance of 1 in model performance test (random forest stochasticity)

## Current status

All R CMD check issues resolved. Tests passing on R 4.5.3.
