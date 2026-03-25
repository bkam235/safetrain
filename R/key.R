#' Generate a random secret key
#'
#' @param bytes Length of key in bytes (default 32 for 256-bit).
#' @return Raw vector of random bytes.
#' @examples
#' k <- generate_key()
#' length(k)  # 32
#' @export
generate_key <- function(bytes = 32L) {
  bytes <- as.integer(bytes)
  if (bytes < 16L) stop("Key must be at least 16 bytes")
  as.raw(sample(0:255, bytes, replace = TRUE))
}

#' Derive a secret key from a passphrase
#'
#' @param passphrase Character string (e.g. password).
#' @param bytes Length of derived key in bytes (default 32).
#' @return Raw vector of derived key bytes.
#' @examples
#' k <- key_from_passphrase("my-secret")
#' @export
key_from_passphrase <- function(passphrase, bytes = 32L) {
  digest::digest(passphrase, algo = "sha256", raw = TRUE)[seq_len(min(bytes, 32L))]
}

#' Normalize key to raw bytes (accept raw or character passphrase)
#' @param key Secret key: raw vector or character (passphrase).
#' @param ... Passed to key_from_passphrase if key is character.
#' @return Raw vector.
#' @noRd
normalize_key <- function(key, ...) {
  if (is.raw(key)) return(key)
  if (is.character(key) && length(key) == 1L) return(key_from_passphrase(key, ...))
  stop("key must be raw bytes or a single character string (passphrase)")
}

#' Derive a column-specific key from the master key (HMAC-based)
#' @param master_key Raw vector.
#' @param column_id Character identifier for the column (e.g. column name).
#' @return Raw vector (32 bytes).
#' @noRd
derive_column_key <- function(master_key, column_id) {
  digest::hmac(master_key, column_id, algo = "sha256", raw = TRUE)
}

#' Generate a deterministic pseudo-random byte stream from a key and label
#'
#' Uses iterated HMAC-SHA256 in counter mode: block_i = HMAC(key, "label|i").
#' Each call produces 32 bytes; blocks are concatenated and truncated to
#' \code{n_bytes}.
#'
#' @param seed_key Raw vector (secret key).
#' @param label Character string (domain separator).
#' @param n_bytes Number of pseudo-random bytes to generate.
#' @return Raw vector of length \code{n_bytes}.
#' @noRd
hmac_prng_stream <- function(seed_key, label, n_bytes) {
  n_blocks <- ceiling(n_bytes / 32L)
  out <- raw(n_blocks * 32L)
  for (i in seq_len(n_blocks)) {
    block <- digest::hmac(seed_key, paste0(label, "|", i), algo = "sha256", raw = TRUE)
    out[((i - 1L) * 32L + 1L):(i * 32L)] <- block
  }
  out[seq_len(n_bytes)]
}
