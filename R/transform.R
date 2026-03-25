# Per-column transforms: categorical (keyed tokenization), numeric (affine)

#' Anonymize a categorical/character vector with keyed tokenization
#'
#' Maps each distinct value to a deterministic anonymized label (HMAC-based).
#' Preserves cardinality and equality; same value always maps to same token.
#'
#' @param x Character or factor vector.
#' @param col_key Raw vector (column-specific key from derive_column_key).
#' @return List with anonymized vector (same type as x) and mapping (plaintext -> ciphertext).
#' @noRd
transform_categorical <- function(x, col_key) {
  is_factor <- is.factor(x)
  if (is_factor) {
    lvls <- levels(x)
    x_char <- as.character(x)
  } else {
    lvls <- NULL
    x_char <- as.character(x)
  }
  uniq <- unique(na.omit(x_char))
  mapping <- character(length(uniq))
  names(mapping) <- uniq
  for (v in uniq) {
    h <- digest::hmac(col_key, v, algo = "sha256", raw = TRUE)
    hexpart <- paste(format(as.hexmode(as.integer(h[1:8]))), collapse = character(1L))
    mapping[v] <- paste0("_", hexpart)
  }
  out <- mapping[x_char]
  out[is.na(x_char)] <- NA_character_
  if (is_factor) {
    anon_levels <- unique(out[!is.na(out)])
    out <- factor(out, levels = anon_levels)
  }
  list(values = out, mapping = mapping, levels_orig = lvls)
}

#' Reverse categorical transform using stored mapping
#' @param x Anonymized character/factor vector.
#' @param mapping Named character: anonymized -> original.
#' @param levels_orig Original factor levels or NULL.
#' @noRd
untransform_categorical <- function(x, mapping, levels_orig = NULL) {
  rev_map <- setNames(names(mapping), mapping)
  x_char <- as.character(x)
  out <- rev_map[x_char]
  out[is.na(x_char)] <- NA_character_
  if (!is.null(levels_orig)) {
    out <- factor(out, levels = levels_orig)
  }
  out
}

#' Anonymize a numeric vector with keyed affine transform: a*x + b
#'
#' a and b are derived from col_key so the transform is deterministic and reversible.
#' Order is preserved (a > 0).
#'
#' @param x Numeric vector.
#' @param col_key Raw vector (column-specific key).
#' @return List with anonymized numeric vector and list (a, b) for reversal.
#' @noRd
transform_numeric <- function(x, col_key) {
  h <- digest::hmac(col_key, "affine", algo = "sha256", raw = TRUE)
  # Use first 8 bytes for a (scale), next 8 for b (shift). Ensure a > 0 and not too small.
  a_bytes <- as.integer(h[1:4])
  a <- 1 + (sum(a_bytes * 256^(0:3)) %% 1e6) / 1e6
  b_bytes <- as.integer(h[5:8])
  b <- (sum(b_bytes * 256^(0:3)) %% 1e8) - 5e7
  out <- a * x + b
  list(values = out, coeff = list(a = a, b = b))
}

#' Reverse numeric affine transform
#' @param x Anonymized numeric vector.
#' @param coeff List with a and b.
#' @noRd
untransform_numeric <- function(x, coeff) {
  a <- coeff$a
  b <- coeff$b
  (x - b) / a
}

# ---------------------------------------------------------------------------
# Crypto helper functions for key-dependent PCA
# ---------------------------------------------------------------------------

#' Bitwise XOR of two raw vectors
#' @param a Raw vector.
#' @param b Raw vector (same length as a).
#' @return Raw vector of same length.
#' @noRd
xor_raw <- function(a, b) {
  as.raw(bitwXor(as.integer(a), as.integer(b)))
}

#' Convert raw bytes to uniform (0, 1) values
#'
#' Each value consumes 4 bytes interpreted as a little-endian uint32.
#'
#' @param raw_bytes Raw vector (length >= 4 * n).
#' @param n Number of uniform values to produce.
#' @return Numeric vector of length n, values in (0, 1).
#' @noRd
bytes_to_uniforms <- function(raw_bytes, n) {
  out <- numeric(n)
  for (i in seq_len(n)) {
    offset <- (i - 1L) * 4L + 1L
    bytes4 <- as.integer(raw_bytes[offset:(offset + 3L)])
    uint32 <- sum(bytes4 * 256^(0:3))
    out[i] <- (uint32 + 0.5) / 4294967296
  }
  out
}

#' Box-Muller transform: pairs of uniforms to standard normals
#' @param uniforms Numeric vector of U(0,1) values (length must be even).
#' @return Numeric vector of standard normal values (same length).
#' @noRd
box_muller <- function(uniforms) {
  n <- length(uniforms)
  n_pairs <- n %/% 2L
  u1 <- uniforms[seq(1L, 2L * n_pairs, by = 2L)]
  u2 <- uniforms[seq(2L, 2L * n_pairs, by = 2L)]
  z1 <- sqrt(-2 * log(u1)) * cos(2 * pi * u2)
  z2 <- sqrt(-2 * log(u1)) * sin(2 * pi * u2)
  c(z1, z2)
}

#' Generate a key-derived n x n orthogonal rotation matrix
#'
#' Uses HMAC-PRNG to fill a Gaussian matrix, then QR decomposition.
#' Sign of each column is fixed so that diag(R) > 0, making the
#' mapping from key to Q deterministic and unique.
#'
#' @param key Raw vector (secret key).
#' @param n Integer dimension.
#' @return n x n orthogonal matrix Q.
#' @noRd
generate_key_rotation <- function(key, n) {
  n_normals <- n * n
  # Need 2 uniforms per normal (Box-Muller), 4 bytes per uniform
  n_uniforms <- 2L * n_normals
  n_bytes <- 4L * n_uniforms
  raw_bytes <- hmac_prng_stream(key, "rotation-matrix", n_bytes)
  uniforms <- bytes_to_uniforms(raw_bytes, n_uniforms)
  normals <- box_muller(uniforms)
  G <- matrix(normals[seq_len(n_normals)], nrow = n, ncol = n)
  qr_decomp <- qr(G)
  Q <- qr.Q(qr_decomp)
  R <- qr.R(qr_decomp)
  signs <- sign(diag(R))
  signs[signs == 0] <- 1
  Q <- Q %*% diag(signs, nrow = n)
  Q
}

#' Derive key-based center and scale vectors for columns
#'
#' Center values lie in (-1000, 1000); scale values in (0.5, 2.0).
#' These are NOT stored in the mapping — they are re-derived from the key.
#'
#' @param key Raw vector (secret key).
#' @param col_names Character vector of column names.
#' @return List with numeric vectors `center` and `scale`.
#' @noRd
derive_center_scale <- function(key, col_names) {
  n <- length(col_names)
  centers <- numeric(n)
  scales <- numeric(n)
  for (i in seq_along(col_names)) {
    raw_bytes <- hmac_prng_stream(key, paste0("center-scale-", col_names[i]), 8L)
    u <- bytes_to_uniforms(raw_bytes, 2L)
    centers[i] <- u[1L] * 2000 - 1000
    scales[i] <- u[2L] * 1.5 + 0.5
  }
  list(center = centers, scale = scales)
}

#' Encrypt a numeric vector (the dropped column) with key-derived XOR stream
#'
#' Serializes doubles to raw bytes via writeBin, XORs with a PRNG keystream.
#'
#' @param values Numeric vector.
#' @param key Raw vector (secret key).
#' @return Raw vector (encrypted bytes).
#' @noRd
encrypt_dropped_column <- function(values, key) {
  raw_data <- writeBin(values, raw(), size = 8L, endian = "little")
  n_bytes <- length(raw_data)
  keystream <- hmac_prng_stream(key, "dropped-column", n_bytes)
  xor_raw(raw_data, keystream)
}

#' Decrypt a dropped column from encrypted raw bytes
#'
#' Reverses encrypt_dropped_column: XOR with same keystream, then readBin.
#'
#' @param encrypted Raw vector (encrypted bytes from encrypt_dropped_column).
#' @param key Raw vector (secret key).
#' @return Numeric vector of doubles.
#' @noRd
decrypt_dropped_column <- function(encrypted, key) {
  n_bytes <- length(encrypted)
  keystream <- hmac_prng_stream(key, "dropped-column", n_bytes)
  raw_data <- xor_raw(encrypted, keystream)
  readBin(raw_data, double(), n = n_bytes %/% 8L, size = 8L, endian = "little")
}

# ---------------------------------------------------------------------------
# Key-dependent PCA transform and inverse
# ---------------------------------------------------------------------------

#' Anonymize a matrix of numeric columns with key-dependent rotation
#'
#' Applies key-derived centering/scaling, key-derived orthogonal rotation,
#' and drops the last column (encrypting it for storage in the mapping).
#' Without the key, the rotation and center/scale cannot be re-derived,
#' making the transform irreversible.
#'
#' @param mat Numeric matrix (rows = observations, cols = variables).
#' @param key Raw vector (secret key).
#' @return List with `values` (reduced score matrix, one fewer column) and
#'   `pca_info` (metadata for reversal: n_original_cols, col_names,
#'   encrypted_dropped).
#' @noRd
transform_numeric_pca <- function(mat, key) {
  n_cols <- ncol(mat)
  col_names <- colnames(mat)

  # Key-derived center and scale
  cs <- derive_center_scale(key, col_names)
  mat_cs <- sweep(mat, 2, cs$center, `-`)
  mat_cs <- sweep(mat_cs, 2, cs$scale, `/`)

  # Key-derived orthogonal rotation
  Q <- generate_key_rotation(key, n_cols)
  mat_rot <- mat_cs %*% Q

  # Drop last column and encrypt it (when >= 2 columns)
  if (n_cols >= 2L) {
    dropped <- mat_rot[, n_cols]
    encrypted_dropped <- encrypt_dropped_column(dropped, key)
    mat_out <- mat_rot[, -n_cols, drop = FALSE]
  } else {
    # Single column: no drop (degenerate case)
    encrypted_dropped <- raw(0L)
    mat_out <- mat_rot
  }

  list(
    values   = mat_out,
    pca_info = list(
      n_original_cols   = n_cols,
      col_names         = col_names,
      encrypted_dropped = encrypted_dropped
    )
  )
}

#' Reverse key-dependent PCA transform
#'
#' Decrypts the dropped column, reconstructs the full rotated matrix,
#' re-derives Q from the key for inverse rotation, and reverses
#' center/scale.
#'
#' @param scores Reduced score matrix (one fewer column than original).
#' @param pca_info List from transform_numeric_pca (n_original_cols,
#'   col_names, encrypted_dropped).
#' @param key Raw vector (secret key).
#' @return Numeric matrix with original dimensions and values.
#' @noRd
untransform_numeric_pca <- function(scores, pca_info, key) {
  n_cols <- pca_info$n_original_cols
  col_names <- pca_info$col_names

  # Reconstruct full rotated matrix
  if (n_cols >= 2L) {
    dropped <- decrypt_dropped_column(pca_info$encrypted_dropped, key)
    mat_rot <- cbind(scores, dropped)
  } else {
    mat_rot <- scores
  }

  # Inverse rotation
  Q <- generate_key_rotation(key, n_cols)
  mat_cs <- mat_rot %*% t(Q)

  # Reverse center and scale
  cs <- derive_center_scale(key, col_names)
  mat_orig <- sweep(mat_cs, 2, cs$scale, `*`)
  mat_orig <- sweep(mat_orig, 2, cs$center, `+`)
  colnames(mat_orig) <- col_names

  mat_orig
}

#' Encode a single column to a plain numeric vector for PCA input
#'
#' Converts each column type to a numeric vector:
#' - integer/numeric: as.numeric(), preserved as-is
#' - categorical/factor/logical: 0-indexed integer label codes
#' - Date: days since epoch (as.numeric)
#' - POSIXt: seconds since epoch (as.numeric)
#'
#' Returns the numeric values and the metadata needed to reverse via
#' decode_column().
#'
#' @param x Column vector.
#' @return List with `values` (numeric vector) and type metadata.
#' @noRd
encode_column <- function(x) {
  if (inherits(x, "Date")) {
    return(list(values = as.numeric(x), type = "date", origin = "1970-01-01"))
  }
  if (inherits(x, "POSIXt")) {
    return(list(values = as.numeric(x), type = "datetime", origin = "1970-01-01 00:00:00"))
  }
  if (is.integer(x)) {
    return(list(values = as.numeric(x), type = "integer"))
  }
  if (is.numeric(x)) {
    return(list(values = as.numeric(x), type = "numeric"))
  }
  # character, factor, logical -> 0-indexed integer label codes
  is_fac      <- is.factor(x)
  levels_orig <- if (is_fac) levels(x) else NULL
  x_char      <- as.character(x)
  labels      <- if (is_fac) levels(x) else sort(unique(x_char[!is.na(x_char)]))
  codes       <- as.numeric(match(x_char, labels) - 1L)
  codes[is.na(x_char)] <- NA_real_
  list(
    values      = codes,
    type        = if (is_fac) "factor" else "categorical",
    labels      = labels,
    levels_orig = levels_orig
  )
}

#' Decode a numeric vector back to its original column type
#'
#' Reverses encode_column() using the stored metadata. Integer, date,
#' datetime, and categorical columns are rounded before conversion to
#' absorb floating-point error from the PCA round-trip.
#'
#' @param num_vec Numeric vector (column of the inverse-PCA matrix).
#' @param enc Encoding metadata list returned by encode_column().
#' @noRd
decode_column <- function(num_vec, enc) {
  if (enc$type == "numeric") {
    return(as.numeric(num_vec))
  }
  if (enc$type == "integer") {
    return(as.integer(round(num_vec)))
  }
  if (enc$type == "date") {
    return(as.Date(round(num_vec), origin = enc$origin))
  }
  if (enc$type == "datetime") {
    return(as.POSIXct(round(num_vec), origin = enc$origin))
  }
  # categorical or factor: round to nearest 0-indexed label position
  idx <- pmax(1L, pmin(as.integer(round(num_vec)) + 1L, length(enc$labels)))
  out <- enc$labels[idx]
  out[is.na(num_vec)] <- NA_character_
  if (enc$type == "factor") {
    return(factor(out, levels = enc$levels_orig))
  }
  out
}

#' Infer column type for transform selection
#' @param x Column vector.
#' @return One of "numeric", "categorical", "date", "datetime".
#' @noRd
column_type <- function(x) {
  if (inherits(x, "Date")) return("date")
  if (inherits(x, "POSIXt")) return("datetime")
  if (is.numeric(x) || is.integer(x)) return("numeric")
  if (is.character(x) || is.factor(x) || is.logical(x)) return("categorical")
  "categorical"
}

# ---------------------------------------------------------------------------
# Cryptoencoder: trained n->n autoencoder with encryption guarantees
# ---------------------------------------------------------------------------

#' Generate key-derived weight matrices for the cryptoencoder
#'
#' Uses HMAC-PRNG to fill an n x n encoder weight matrix with Xavier-scaled
#' values. Bias vectors are initialized to zero.
#'
#' @param key Raw vector (secret key).
#' @param n Integer, number of columns (input = hidden = output).
#' @param label Character label for PRNG domain separation.
#' @return List with W_enc (n x n matrix), b_enc (length n), b_dec (length n).
#' @noRd
generate_key_weights <- function(key, n, label = "cryptoencoder-weights") {
  n_weights <- n * n
  n_bytes <- 4L * n_weights
  raw_bytes <- hmac_prng_stream(key, label, n_bytes)
  uniforms <- bytes_to_uniforms(raw_bytes, n_weights)

  # Xavier initialization: U(-limit, +limit)
  limit <- sqrt(6 / (2 * n))
  vals <- uniforms * 2 * limit - limit
  W_enc <- matrix(vals, nrow = n, ncol = n)

  list(
    W_enc = W_enc,
    b_enc = rep(0, n),
    b_dec = rep(0, n)
  )
}

#' Autoencoder forward pass
#'
#' Encoder: hidden = tanh(x %*% W_enc + b_enc)
#' Decoder: output = hidden %*% W_dec + b_dec
#'
#' @param x_mat Numeric matrix (N x n).
#' @param W_enc Encoder weight matrix (n x n).
#' @param b_enc Encoder bias vector (length n).
#' @param W_dec Decoder weight matrix (n x n).
#' @param b_dec Decoder bias vector (length n).
#' @return List with hidden (N x n), output (N x n),
#'   h_pre (pre-activation, N x n).
#' @noRd
ae_forward <- function(x_mat, W_enc, b_enc, W_dec, b_dec) {
  N <- nrow(x_mat)
  h_pre <- x_mat %*% W_enc + matrix(b_enc, nrow = N, ncol = length(b_enc),
                                     byrow = TRUE)
  hidden <- tanh(h_pre)
  output <- hidden %*% W_dec + matrix(b_dec, nrow = N, ncol = length(b_dec),
                                      byrow = TRUE)
  list(hidden = hidden, output = output, h_pre = h_pre)
}

#' Train a shallow n->n autoencoder via Adam optimizer
#'
#' Trains a 1-hidden-layer autoencoder (tanh activation, n->n architecture)
#' with minimal reconstruction error. With n->n (no bottleneck), the network
#' has sufficient capacity for near-perfect reconstruction.
#'
#' @param enc_mat Numeric matrix (N x n).
#' @param key Raw vector for deterministic weight initialization.
#' @param max_epochs Maximum training iterations.
#' @param tol Stop when MSE loss falls below this threshold.
#' @param lr Learning rate for Adam optimizer.
#' @return List with weights (W_enc, b_enc, W_dec, b_dec), data_center,
#'   data_scale, final_loss, epochs_run.
#' @noRd
train_cryptoencoder <- function(enc_mat, key, max_epochs = 5000L,
                                tol = 1e-10, lr = 0.01) {
  N <- nrow(enc_mat)
  n <- ncol(enc_mat)

  # Data-derived normalization for stable training
  data_center <- colMeans(enc_mat)
  data_scale <- apply(enc_mat, 2, stats::sd)
  data_scale[data_scale < 1e-12] <- 1  # avoid division by zero
  x_norm <- sweep(enc_mat, 2, data_center, `-`)
  x_norm <- sweep(x_norm, 2, data_scale, `/`)

  # Initialize weights from key (n x n)
  init <- generate_key_weights(key, n)
  W_enc <- init$W_enc
  b_enc <- init$b_enc
  W_dec <- t(W_enc)  # start with tied weights
  b_dec <- init$b_dec

  loss <- Inf
  epochs_run <- 0L

  # Adam optimizer state
  beta1 <- 0.9; beta2 <- 0.999; eps <- 1e-8
  m_We <- 0; v_We <- 0; m_be <- 0; v_be <- 0
  m_Wd <- 0; v_Wd <- 0; m_bd <- 0; v_bd <- 0

  # Learning rate decay: track best loss, reduce lr when stuck
  best_loss <- Inf
  patience <- 500L
  patience_counter <- 0L
  current_lr <- lr

  for (epoch in seq_len(max_epochs)) {
    # Forward pass
    fwd <- ae_forward(x_norm, W_enc, b_enc, W_dec, b_dec)
    residual <- fwd$output - x_norm

    # MSE loss
    loss <- mean(residual^2)
    epochs_run <- epoch
    if (loss < tol) break

    # Learning rate decay
    if (loss < best_loss * 0.999) {
      best_loss <- loss
      patience_counter <- 0L
    } else {
      patience_counter <- patience_counter + 1L
      if (patience_counter >= patience) {
        current_lr <- current_lr * 0.5
        patience_counter <- 0L
        if (current_lr < lr * 1e-4) break  # lr too small, stop
      }
    }

    # Backward pass
    dL_dy <- 2 * residual / N
    dL_dW_dec <- t(fwd$hidden) %*% dL_dy
    dL_db_dec <- colSums(dL_dy)
    dL_dh <- dL_dy %*% t(W_dec)
    dL_dh_pre <- dL_dh * (1 - fwd$hidden^2)  # tanh derivative
    dL_dW_enc <- t(x_norm) %*% dL_dh_pre
    dL_db_enc <- colSums(dL_dh_pre)

    # Adam update
    m_We <- beta1 * m_We + (1 - beta1) * dL_dW_enc
    v_We <- beta2 * v_We + (1 - beta2) * dL_dW_enc^2
    m_be <- beta1 * m_be + (1 - beta1) * dL_db_enc
    v_be <- beta2 * v_be + (1 - beta2) * dL_db_enc^2
    m_Wd <- beta1 * m_Wd + (1 - beta1) * dL_dW_dec
    v_Wd <- beta2 * v_Wd + (1 - beta2) * dL_dW_dec^2
    m_bd <- beta1 * m_bd + (1 - beta1) * dL_db_dec
    v_bd <- beta2 * v_bd + (1 - beta2) * dL_db_dec^2

    bc1 <- 1 - beta1^epoch
    bc2 <- 1 - beta2^epoch
    W_enc <- W_enc - current_lr * (m_We / bc1) / (sqrt(v_We / bc2) + eps)
    b_enc <- b_enc - current_lr * (m_be / bc1) / (sqrt(v_be / bc2) + eps)
    W_dec <- W_dec - current_lr * (m_Wd / bc1) / (sqrt(v_Wd / bc2) + eps)
    b_dec <- b_dec - current_lr * (m_bd / bc1) / (sqrt(v_bd / bc2) + eps)
  }

  list(
    weights = list(W_enc = W_enc, b_enc = b_enc, W_dec = W_dec, b_dec = b_dec),
    data_center = data_center,
    data_scale = data_scale,
    final_loss = loss,
    epochs_run = epochs_run
  )
}

#' Encrypt autoencoder weights and normalization params
#'
#' Serializes weight matrices and data normalization parameters to raw bytes,
#' then XORs with a key-derived stream.
#'
#' @param weights List with W_enc, b_enc, W_dec, b_dec.
#' @param data_center Numeric vector (column means).
#' @param data_scale Numeric vector (column sds).
#' @param key Raw vector (secret key).
#' @return Raw vector (encrypted bytes).
#' @noRd
encrypt_ae_weights <- function(weights, data_center, data_scale, key) {
  n <- nrow(weights$W_enc)
  raw_data <- c(
    writeBin(as.integer(n), raw(), size = 4L, endian = "little"),
    writeBin(as.double(weights$W_enc), raw(), size = 8L, endian = "little"),
    writeBin(as.double(weights$b_enc), raw(), size = 8L, endian = "little"),
    writeBin(as.double(weights$W_dec), raw(), size = 8L, endian = "little"),
    writeBin(as.double(weights$b_dec), raw(), size = 8L, endian = "little"),
    writeBin(as.double(data_center), raw(), size = 8L, endian = "little"),
    writeBin(as.double(data_scale), raw(), size = 8L, endian = "little")
  )
  n_bytes <- length(raw_data)
  keystream <- hmac_prng_stream(key, "ae-weights", n_bytes)
  xor_raw(raw_data, keystream)
}

#' Decrypt autoencoder weights and normalization params
#'
#' Reverses encrypt_ae_weights: XOR with same keystream, then deserialize.
#'
#' @param encrypted Raw vector (from encrypt_ae_weights).
#' @param key Raw vector (secret key).
#' @return List with weights (W_enc, b_enc, W_dec, b_dec), data_center,
#'   data_scale.
#' @noRd
decrypt_ae_weights <- function(encrypted, key) {
  n_bytes <- length(encrypted)
  keystream <- hmac_prng_stream(key, "ae-weights", n_bytes)
  raw_data <- xor_raw(encrypted, keystream)

  # Read header: single dimension (n x n architecture)
  n <- readBin(raw_data[1:4], integer(), n = 1L, size = 4L,
               endian = "little")

  # Validate dimension (wrong key produces garbage)
  if (is.na(n) || n < 1L || n > 10000L) {
    stop("Failed to decrypt cryptoencoder weights (wrong key?)")
  }
  expected_bytes <- 4L + (2L * n * n + n + n + n + n) * 8L
  if (expected_bytes > n_bytes) {
    stop("Failed to decrypt cryptoencoder weights (wrong key?)")
  }

  offset <- 5L
  read_doubles <- function(count) {
    start <- offset
    end <- offset + count * 8L - 1L
    vals <- readBin(raw_data[start:end], double(), n = count, size = 8L,
                    endian = "little")
    offset <<- end + 1L
    vals
  }

  W_enc_vals <- read_doubles(n * n)
  W_enc <- matrix(W_enc_vals, nrow = n, ncol = n)
  b_enc <- read_doubles(n)
  W_dec_vals <- read_doubles(n * n)
  W_dec <- matrix(W_dec_vals, nrow = n, ncol = n)
  b_dec <- read_doubles(n)
  data_center <- read_doubles(n)
  data_scale <- read_doubles(n)

  list(
    weights = list(W_enc = W_enc, b_enc = b_enc, W_dec = W_dec, b_dec = b_dec),
    data_center = data_center,
    data_scale = data_scale
  )
}

#' Anonymize a matrix using a trained n->n cryptoencoder
#'
#' Trains a shallow autoencoder (tanh activation, n->n architecture) on the
#' data, then outputs the hidden activations as the anonymized representation.
#' Every output column depends nonlinearly on ALL input columns. Trained
#' weights are encrypted and stored in the mapping.
#'
#' @param mat Numeric matrix (rows = observations, cols = variables).
#' @param key Raw vector (secret key).
#' @param opts List of options (ae_max_epochs, ae_tol, ae_lr).
#' @return List with values (N x n matrix) and pca_info (metadata).
#' @noRd
transform_numeric_cryptoencoder <- function(mat, key, opts = list()) {
  n_cols <- ncol(mat)
  col_names <- colnames(mat)

  # Key-derived center and scale
  cs <- derive_center_scale(key, col_names)
  mat_cs <- sweep(mat, 2, cs$center, `-`)
  mat_cs <- sweep(mat_cs, 2, cs$scale, `/`)

  # Train n->n autoencoder
  max_epochs <- opts$ae_max_epochs %||% 5000L
  tol <- opts$ae_tol %||% 1e-10
  lr <- opts$ae_lr %||% 0.01
  ae <- train_cryptoencoder(mat_cs, key, max_epochs = max_epochs,
                            tol = tol, lr = lr)

  # Encode: apply trained encoder to normalized data
  x_norm <- sweep(mat_cs, 2, ae$data_center, `-`)
  x_norm <- sweep(x_norm, 2, ae$data_scale, `/`)
  fwd <- ae_forward(x_norm, ae$weights$W_enc, ae$weights$b_enc,
                    ae$weights$W_dec, ae$weights$b_dec)

  # Encrypt trained weights + normalization params
  encrypted_weights <- encrypt_ae_weights(ae$weights, ae$data_center,
                                          ae$data_scale, key)

  list(
    values = fwd$hidden,
    pca_info = list(
      n_original_cols = n_cols,
      col_names = col_names,
      method = "cryptoencoder",
      encrypted_weights = encrypted_weights
    )
  )
}

#' Reverse cryptoencoder transform
#'
#' Decrypts stored weights and applies the decoder network to recover
#' the original data from the hidden activations.
#'
#' @param scores Score matrix (N x n).
#' @param pca_info List from transform_numeric_cryptoencoder.
#' @param key Raw vector (secret key).
#' @return Numeric matrix with original values.
#' @noRd
untransform_numeric_cryptoencoder <- function(scores, pca_info, key) {
  col_names <- pca_info$col_names

  # Decrypt stored weights
  dec <- decrypt_ae_weights(pca_info$encrypted_weights, key)

  # Decoder pass: scores are hidden (tanh) activations
  N <- nrow(scores)
  output <- scores %*% dec$weights$W_dec +
    matrix(dec$weights$b_dec, nrow = N, ncol = length(dec$weights$b_dec),
           byrow = TRUE)

  # Reverse data normalization
  mat_cs <- sweep(output, 2, dec$data_scale, `*`)
  mat_cs <- sweep(mat_cs, 2, dec$data_center, `+`)

  # Reverse key-derived center and scale
  cs <- derive_center_scale(key, col_names)
  mat_orig <- sweep(mat_cs, 2, cs$scale, `*`)
  mat_orig <- sweep(mat_orig, 2, cs$center, `+`)
  colnames(mat_orig) <- col_names

  mat_orig
}
