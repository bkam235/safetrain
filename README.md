# safetrain

Reversible, ML-safe anonymization for tabular data in R.

## The problem

You need to share or process sensitive tabular data — but the raw values must not be exposed. Standard approaches either destroy the statistical structure (hashing, random noise) so that machine-learning models trained on the anonymized data perform poorly, or they are trivially reversible (simple column shuffling, linear scaling). **safetrain** sits in between: it produces anonymized data that is *cryptographically irreversible* without the secret key, yet *exactly recoverable* with it, and preserves enough statistical structure for downstream ML.

## How it works

Given a data frame and a secret key, `anonymize_data()` transforms all selected columns jointly into a new set of anonymous columns (`anon_1`, `anon_2`, ...). The transformation is deterministic — the same key and data always produce the same output — and reversible only with the original key.

Two transformation methods are available:

### PCA method (default)

All columns are encoded to numeric (categoricals to integer codes, dates to epoch values), then:

1. **Centered and scaled** using values derived from the key via HMAC-SHA256. These parameters are never stored — they can only be re-derived from the key.
2. **Rotated** by a key-derived orthogonal matrix (HMAC-PRNG generates a Gaussian matrix, QR decomposition orthogonalizes it). The rotation matrix is never stored.
3. **One column is dropped** from the rotated result. The dropped column is encrypted with a key-derived XOR keystream and stored in the mapping.

Output has `n - 1` columns. Recovery is exact within floating-point tolerance (~1e-8).

### Cryptoencoder method

A shallow autoencoder (one hidden layer, tanh activation) is trained directly on the data to learn a nonlinear, key-dependent encoding. Unlike the PCA method, no columns are dropped — the output has the **same number of columns** as the input.

1. **Encode** all columns to numeric (same as PCA).
2. **Center and scale** using key-derived values (same as PCA; never stored).
3. **Normalize** using data-derived statistics (stored encrypted in the mapping).
4. **Train** an n-to-n autoencoder on the normalized data. Weights are initialized deterministically from the key (HMAC-PRNG + Xavier scaling). An Adam optimizer with learning-rate decay trains the network to near-zero reconstruction loss.
5. **Encode** the data through the trained encoder, producing n hidden-layer activations (all values in (-1, 1) due to tanh).
6. **Encrypt** the trained weights and normalization parameters with a key-derived XOR stream and store them in the mapping.

The anonymized output is the encoder's hidden activations — a nonlinear, key-dependent remix of the original values. Recovery applies the decoder network, reverses normalization, and reverses the key-derived centering/scaling. Reconstruction tolerance is ~1e-4 (the n-to-n architecture has enough capacity for near-perfect reconstruction).

## Theoretical guarantees (cryptoencoder)

The cryptoencoder provides formal guarantees that the anonymized data cannot be trivially mapped back to the original, even with access to both data frames:

**No column correspondence.** Every output column is a nonlinear function of *all* input columns:

```
h_j = tanh( x_1 * W_1j + x_2 * W_2j + ... + x_n * W_nj + b_j )
```

Changing any single input column changes every output column. There is no 1-to-1 mapping between original and anonymized columns. This is verified by test: perturbing one input column causes all output columns to differ.

**No cell correspondence.** Cell (i, j) in the anonymized output depends on every cell in row i of the original data, weighted by the trained (and encrypted) weight matrix. Without the key, the weight matrix cannot be decrypted, so individual cell values cannot be traced back. No output column has a correlation above 0.99 with any single input column (verified by test).

**Irreversibility without key.** The centering, scaling, and rotation parameters are derived from the key and never stored. The trained autoencoder weights are encrypted with a key-derived XOR stream. The mapping object alone is insufficient for reversal — both the key and the mapping are required.

**Diffeomorphism.** With a full-rank encoder weight matrix, the encoder is a smooth, invertible map. This means ML models trained on the anonymized data have the same theoretical expressive power as models trained on the original data.

## Installation

From source (e.g. after cloning):

```r
install.packages("path/to/safetrain", repos = NULL, type = "source")
# or
devtools::install_local("path/to/safetrain")
```

Dependency: **digest** (Imports). For tests and vignette: **testthat**, **ranger**, **knitr**, **rmarkdown** (Suggests).

## Quick example

```r
library(safetrain)

key <- generate_key()          # random 256-bit key
data(sample_data)

# --- PCA method (default): output has n-1 columns ---
res <- anonymize_data(sample_data, key)
res$data    # anonymized data frame
res$mapping # metadata needed for reversal

# --- Cryptoencoder method: output has n columns, stronger guarantees ---
res <- anonymize_data(sample_data, key, opts = list(method = "cryptoencoder"))
res$data    # all values in (-1, 1), every column mixes all inputs

# Reverse with the same key
recovered <- deanonymize_data(res$data, key, res$mapping)
all.equal(recovered, sample_data)  # TRUE (within tolerance)
```

You can use a passphrase instead of a random key:

```r
key <- key_from_passphrase("my-secret")
```

To anonymize only specific columns:

```r
res <- anonymize_data(data, key, columns = c("amount", "count"))
```

## API

| Function | Purpose |
|---|---|
| `generate_key(bytes = 32)` | Generate a random 256-bit key (raw vector) |
| `key_from_passphrase(passphrase)` | Derive a deterministic key from a passphrase (SHA-256) |
| `anonymize_data(data, key, columns, opts)` | Anonymize a data frame. Returns `list(data, mapping)` |
| `deanonymize_data(data_anon, key, mapping)` | Reverse anonymization. Returns the original data frame |

### Options for `anonymize_data()`

Pass a named list as `opts`:

| Option | Default | Description |
|---|---|---|
| `method` | `"pca"` | `"pca"` or `"cryptoencoder"` |
| `ae_max_epochs` | 5000 | Max training epochs (cryptoencoder only) |
| `ae_tol` | 1e-10 | Early-stopping loss threshold (cryptoencoder only) |
| `ae_lr` | 0.01 | Initial learning rate (cryptoencoder only) |

## Choosing a method

| | PCA | Cryptoencoder |
|---|---|---|
| Output columns | n - 1 | n (same as input) |
| Recovery precision | ~1e-8 (exact) | ~1e-4 (near-exact) |
| Column mixing | Linear (rotation) | Nonlinear (tanh) |
| Speed | Instant | Trains per dataset |
| Column/cell traceability | Not 1-to-1 (rotation) | Guaranteed no correspondence |

Use **PCA** when you need exact recovery and speed. Use **cryptoencoder** when you need the same column count, stronger anonymization guarantees, or better preservation of ML signal (no column is dropped).

## Vignette

See the vignette **ML-Safe Anonymization** for usage and a model-performance comparison:

```r
vignette("ml-safe-anonymization", package = "safetrain")
```

## License

MIT
