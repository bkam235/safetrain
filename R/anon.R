#' Anonymize a data frame with key-based reversible transforms
#'
#' All selected columns are encoded to numeric (categorical to label codes,
#' dates to epoch values), then transformed jointly. The default method
#' (`"pca"`) uses a key-dependent orthogonal rotation and drops one column;
#' `"cryptoencoder"` trains a shallow n-to-n autoencoder where every output
#' depends nonlinearly on all inputs, preserving the column count.
#'
#' @param data A data.frame.
#' @param key Secret key: raw bytes (e.g. from `generate_key()`) or character
#'   passphrase. The key drives the rotation, centering, scaling, and
#'   encryption — different keys produce different anonymized output.
#' @param columns Character vector of column names to anonymize, or NULL to
#'   anonymize all columns.
#' @param opts Named list of options:
#'   \describe{
#'     \item{method}{Transformation method: `"pca"` (default) or
#'       `"cryptoencoder"`.}
#'     \item{ae_max_epochs}{Maximum training epochs for the cryptoencoder
#'       (default 5000). Ignored for `"pca"`.}
#'     \item{ae_tol}{Early-stopping tolerance for cryptoencoder training loss
#'       (default 1e-10). Ignored for `"pca"`.}
#'     \item{ae_lr}{Learning rate for cryptoencoder training (default 0.01).
#'       Ignored for `"pca"`.}
#'   }
#' @return List with `data` (anonymized data.frame) and `mapping` (metadata
#'   needed for reversal). For `"pca"`, output has one fewer column; for
#'   `"cryptoencoder"`, output has the same number of columns.
#' @export
anonymize_data <- function(data, key, columns = NULL, opts = list()) {
  if (!is.data.frame(data)) stop("data must be a data.frame")
  key <- normalize_key(key)
  nms <- names(data)
  if (is.null(columns)) columns <- nms
  columns <- intersect(columns, nms)
  if (length(columns) == 0L) return(list(data = data, mapping = list(columns = character(0))))

  method <- opts$method %||% "pca"
  if (!method %in% c("pca", "cryptoencoder")) {
    stop("opts$method must be one of 'pca', 'cryptoencoder'")
  }

  # Encode every column to numeric (label-encode categoricals, epoch for dates).
  col_encodings <- lapply(setNames(columns, columns), function(col) encode_column(data[[col]]))

  # Build the encoded matrix: one column per variable, one row per observation.
  enc_mat <- vapply(col_encodings, function(e) e$values, numeric(nrow(data)))
  if (is.null(dim(enc_mat))) {
    enc_mat <- matrix(enc_mat, ncol = 1L)
  }
  colnames(enc_mat) <- columns

  # Key-dependent transform.
  if (method == "pca") {
    transform_res <- transform_numeric_pca(enc_mat, key)
  } else {
    transform_res <- transform_numeric_cryptoencoder(enc_mat, key, opts)
  }

  # Build output: non-anonymized columns + anonymized columns (anon_1, ...).
  non_anon_cols <- setdiff(nms, columns)
  out <- data[, non_anon_cols, drop = FALSE]
  n_anon_cols <- ncol(transform_res$values)
  anon_names <- character(0)
  if (n_anon_cols > 0L) {
    anon_names <- paste0("anon_", seq_len(n_anon_cols))
    for (i in seq_len(n_anon_cols)) {
      out[[anon_names[i]]] <- transform_res$values[, i]
    }
  }

  list(
    data    = out,
    mapping = list(
      version       = if (method == "pca") 2L else 3L,
      method        = method,
      columns       = columns,
      anon_names    = anon_names,
      non_anon_cols = non_anon_cols,
      original_names = nms,
      pca           = transform_res$pca_info,
      col_encodings = col_encodings
    )
  )
}

#' Apply an existing anonymization mapping to new data
#'
#' Transforms new observations using the encoder trained during a previous
#' call to [anonymize_data()].  Unlike [anonymize_data()], no autoencoder is
#' retrained: the encrypted weights stored in \code{mapping} are decrypted and
#' applied directly, so the new data lands in the same representation space as
#' the original anonymized data.
#'
#' This is the correct pattern for production use: anonymize a training set
#' with [anonymize_data()], then pass the returned \code{mapping} here to
#' transform held-out or streaming data consistently.
#'
#' Only \code{method = "cryptoencoder"} mappings are supported.  For
#' \code{method = "pca"} the key-derived rotation is already fully
#' data-independent, so calling [anonymize_data()] directly on new data already
#' produces a consistent representation.
#'
#' @param new_data A data.frame with the same feature columns that were
#'   anonymized when \code{mapping} was created.
#' @param key The same secret key used to create \code{mapping}.
#' @param mapping The \code{mapping} list returned by [anonymize_data()].
#' @return A data.frame with the same layout as \code{anonymize_data()$data}:
#'   non-anonymized columns preserved, anonymized columns replaced by
#'   \code{anon_1, ..., anon_n}.
#' @export
transform_new_data <- function(new_data, key, mapping) {
  if (!is.data.frame(new_data)) stop("new_data must be a data.frame")
  key <- normalize_key(key)

  method <- mapping$method %||% "pca"
  if (method == "pca") {
    stop(
      "transform_new_data() does not support method = \"pca\". ",
      "For PCA, call anonymize_data() directly: the key-derived rotation ",
      "is data-independent and already produces a consistent representation."
    )
  }

  columns <- mapping$columns
  missing_cols <- setdiff(columns, names(new_data))
  if (length(missing_cols) > 0L) {
    stop("new_data is missing columns that were anonymized: ",
         paste(missing_cols, collapse = ", "))
  }

  # Encode each column to numeric, reusing the original label ordering for
  # categorical columns so category codes are consistent with training data.
  enc_mat <- matrix(NA_real_, nrow = nrow(new_data), ncol = length(columns))
  colnames(enc_mat) <- columns
  for (i in seq_along(columns)) {
    enc_mat[, i] <- encode_column_with_meta(
      new_data[[columns[i]]], mapping$col_encodings[[columns[i]]]
    )
  }

  # Re-derive key-based center/scale (never stored; same derivation as original).
  cs <- derive_center_scale(key, columns)
  mat_cs <- sweep(enc_mat, 2, cs$center, `-`)
  mat_cs <- sweep(mat_cs, 2, cs$scale, `/`)

  # Decrypt the trained autoencoder weights from the mapping.
  dec <- decrypt_ae_weights(mapping$pca$encrypted_weights, key)

  # Normalize using the training data's statistics (stored in encrypted weights).
  x_norm <- sweep(mat_cs, 2, dec$data_center, `-`)
  x_norm <- sweep(x_norm, 2, dec$data_scale, `/`)

  # Encoder forward pass: hidden = tanh(x_norm %*% W_enc + b_enc).
  N <- nrow(x_norm)
  n <- ncol(x_norm)
  h_pre  <- x_norm %*% dec$weights$W_enc +
    matrix(dec$weights$b_enc, nrow = N, ncol = n, byrow = TRUE)
  hidden <- tanh(h_pre)

  # Key-derived post-rotation (same label as used during anonymization).
  Q_post <- generate_key_rotation(key, n, label = "post-encoder-rotation")
  hidden_rotated <- hidden %*% Q_post

  # Assemble output: non-anonymized columns + anon_* columns.
  out <- new_data[, mapping$non_anon_cols, drop = FALSE]
  for (i in seq_along(mapping$anon_names)) {
    out[[mapping$anon_names[i]]] <- hidden_rotated[, i]
  }
  out
}

#' Deanonymize a data frame using key and mapping
#'
#' Reverses the anonymization produced by `anonymize_data()`. The secret key
#' is required to re-derive the rotation matrix and centering/scaling, and to
#' decrypt the dropped column.
#'
#' @param data_anon Anonymized data.frame (as returned by
#'   `anonymize_data()$data`).
#' @param key Same secret key used for anonymization (raw or passphrase).
#' @param mapping_or_schema The mapping object returned by `anonymize_data()`.
#' @return Data.frame with original values restored.
#' @export
deanonymize_data <- function(data_anon, key, mapping_or_schema) {
  if (!is.data.frame(data_anon)) stop("data_anon must be a data.frame")
  mapping <- mapping_or_schema
  if (is.null(mapping$pca) || length(mapping$columns) == 0L) return(data_anon)
  key <- normalize_key(key)

  # Extract anonymized columns into a score matrix.
  anon_names <- mapping$anon_names
  if (length(anon_names) > 0L) {
    score_mat <- as.matrix(data_anon[, anon_names, drop = FALSE])
  } else {
    score_mat <- matrix(nrow = nrow(data_anon), ncol = 0L)
  }

  # Inverse transform: dispatch by method (backward compat: missing = pca).
  method <- mapping$method %||% "pca"
  if (method == "pca") {
    enc_mat <- untransform_numeric_pca(score_mat, mapping$pca, key)
  } else {
    enc_mat <- untransform_numeric_cryptoencoder(score_mat, mapping$pca, key)
  }

  # Decode each column from its numeric representation back to original type.
  columns <- mapping$columns
  out <- data_anon[, mapping$non_anon_cols, drop = FALSE]
  for (i in seq_along(columns)) {
    out[[columns[i]]] <- decode_column(enc_mat[, i], mapping$col_encodings[[columns[i]]])
  }

  # Restore original column order.
  out <- out[, mapping$original_names, drop = FALSE]
  out
}
