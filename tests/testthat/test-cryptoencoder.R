# ---------------------------------------------------------------------------
# Unit tests: cryptoencoder internals
# ---------------------------------------------------------------------------

test_that("generate_key_weights produces correct dimensions (n x n)", {
  key <- generate_key()
  w <- generate_key_weights(key, n = 5)
  expect_equal(dim(w$W_enc), c(5, 5))
  expect_length(w$b_enc, 5)
  expect_length(w$b_dec, 5)
})

test_that("generate_key_weights is deterministic for same key", {
  key <- key_from_passphrase("test-key")
  w1 <- generate_key_weights(key, 5)
  w2 <- generate_key_weights(key, 5)
  expect_identical(w1, w2)
})

test_that("generate_key_weights differs for different keys", {
  k1 <- key_from_passphrase("key-a")
  k2 <- key_from_passphrase("key-b")
  w1 <- generate_key_weights(k1, 5)
  w2 <- generate_key_weights(k2, 5)
  expect_false(identical(w1$W_enc, w2$W_enc))
})

test_that("ae_forward produces correct dimensions with n->n", {
  N <- 10; n <- 5
  x <- matrix(rnorm(N * n), nrow = N)
  key <- generate_key()
  w <- generate_key_weights(key, n)
  W_dec <- t(w$W_enc)
  fwd <- ae_forward(x, w$W_enc, w$b_enc, W_dec, w$b_dec)
  expect_equal(dim(fwd$hidden), c(N, n))
  expect_equal(dim(fwd$output), c(N, n))
  expect_equal(dim(fwd$h_pre), c(N, n))
  # Hidden layer uses tanh: all values in (-1, 1)
  expect_true(all(fwd$hidden > -1 & fwd$hidden < 1))
})

test_that("train_cryptoencoder converges to near-zero loss with n->n", {
  set.seed(1)
  x <- matrix(rnorm(100 * 4), ncol = 4)
  colnames(x) <- paste0("V", 1:4)
  key <- key_from_passphrase("train-test")
  ae <- train_cryptoencoder(x, key, max_epochs = 500, lr = 0.01)
  # n->n has enough capacity for near-zero loss
  expect_true(ae$final_loss < 0.01)
  expect_true(ae$epochs_run >= 1)
})

test_that("train_cryptoencoder is deterministic for same key and data", {
  set.seed(1)
  x <- matrix(rnorm(50 * 3), ncol = 3)
  colnames(x) <- paste0("V", 1:3)
  key <- key_from_passphrase("det-test")
  ae1 <- train_cryptoencoder(x, key, max_epochs = 50)
  ae2 <- train_cryptoencoder(x, key, max_epochs = 50)
  expect_equal(ae1$weights$W_enc, ae2$weights$W_enc)
  expect_equal(ae1$final_loss, ae2$final_loss)
})

test_that("encrypt/decrypt ae_weights round-trip is exact", {
  key <- key_from_passphrase("crypt-test")
  w <- list(
    W_enc = matrix(rnorm(16), 4, 4),
    b_enc = rnorm(4),
    W_dec = matrix(rnorm(16), 4, 4),
    b_dec = rnorm(4)
  )
  dc <- rnorm(4)
  ds <- abs(rnorm(4)) + 0.5
  enc <- encrypt_ae_weights(w, dc, ds, key)
  dec <- decrypt_ae_weights(enc, key)
  expect_equal(dec$weights$W_enc, w$W_enc)
  expect_equal(dec$weights$b_enc, w$b_enc)
  expect_equal(dec$weights$W_dec, w$W_dec)
  expect_equal(dec$weights$b_dec, w$b_dec)
  expect_equal(dec$data_center, dc)
  expect_equal(dec$data_scale, ds)
})

# ---------------------------------------------------------------------------
# Integration tests: method = "cryptoencoder"
# ---------------------------------------------------------------------------

test_that("cryptoencoder output has same number of columns as input", {
  key <- generate_key()
  res <- anonymize_data(sample_data, key, opts = list(method = "cryptoencoder"))
  n_orig <- ncol(sample_data)
  # n->n: same number of columns
  expect_equal(ncol(res$data), n_orig)
  expect_equal(res$mapping$method, "cryptoencoder")
  expect_true(!is.null(res$mapping$pca$encrypted_weights))
})

test_that("cryptoencoder round-trip recovers data accurately", {
  key <- key_from_passphrase("ce-roundtrip")
  res <- anonymize_data(sample_data, key, opts = list(method = "cryptoencoder"))
  recovered <- deanonymize_data(res$data, key, res$mapping)
  # n->n tanh autoencoder achieves very good but not bit-exact reconstruction;
  # tolerance reflects the nonlinear activation's inherent approximation error.
  expect_equal(recovered$amount, sample_data$amount, tolerance = 0.05)
  expect_equal(recovered$count, sample_data$count, tolerance = 0.05)
  expect_equal(as.character(recovered$region), as.character(sample_data$region))
  expect_equal(as.character(recovered$product), as.character(sample_data$product))
})

test_that("cryptoencoder round-trip works for all column types", {
  key <- key_from_passphrase("types-test")
  d <- data.frame(
    num = c(1.5, 2.3, 3.7),
    int = 1:3,
    cat = c("a", "b", "a"),
    fac = factor(c("x", "y", "x")),
    dt  = as.Date(c("2020-01-01", "2020-06-15", "2021-03-30"))
  )
  res <- anonymize_data(d, key, opts = list(method = "cryptoencoder"))
  recovered <- deanonymize_data(res$data, key, res$mapping)
  expect_equal(recovered$num, d$num, tolerance = 0.05)
  expect_equal(recovered$int, d$int, tolerance = 0.05)
  expect_equal(recovered$cat, d$cat)
  expect_equal(recovered$fac, d$fac)
  expect_equal(recovered$dt, d$dt, tolerance = 1)
})

test_that("cryptoencoder works with single column", {
  key <- key_from_passphrase("single-col")
  d <- data.frame(x = c(10, 20, 30, 40, 50))
  res <- anonymize_data(d, key, columns = "x",
                        opts = list(method = "cryptoencoder"))
  expect_equal(ncol(res$data), 1)
  recovered <- deanonymize_data(res$data, key, res$mapping)
  expect_equal(recovered$x, d$x, tolerance = 0.02)
})

test_that("cryptoencoder output is deterministic", {
  key <- key_from_passphrase("det")
  r1 <- anonymize_data(sample_data, key, opts = list(method = "cryptoencoder"))
  r2 <- anonymize_data(sample_data, key, opts = list(method = "cryptoencoder"))
  expect_equal(r1$data, r2$data)
})

test_that("cryptoencoder output differs with different keys", {
  k1 <- key_from_passphrase("key-1")
  k2 <- key_from_passphrase("key-2")
  r1 <- anonymize_data(sample_data, k1, opts = list(method = "cryptoencoder"))
  r2 <- anonymize_data(sample_data, k2, opts = list(method = "cryptoencoder"))
  expect_false(identical(r1$data, r2$data))
})

test_that("cryptoencoder wrong key does not recover original data", {
  k1 <- key_from_passphrase("correct")
  k2 <- key_from_passphrase("wrong")
  res <- anonymize_data(sample_data, k1, opts = list(method = "cryptoencoder"))
  result <- tryCatch(
    deanonymize_data(res$data, k2, res$mapping),
    error = function(e) "error"
  )
  if (identical(result, "error")) {
    succeed("wrong key caused decryption error (expected)")
  } else {
    expect_false(isTRUE(all.equal(result$amount, sample_data$amount,
                                  tolerance = 1)))
  }
})

# ---------------------------------------------------------------------------
# Theoretical guarantee tests
# ---------------------------------------------------------------------------

test_that("every output column depends on all input columns (column mixing)", {
  key <- key_from_passphrase("mixing-test")
  d <- data.frame(a = rnorm(20), b = rnorm(20), c = rnorm(20))
  res <- anonymize_data(d, key, opts = list(method = "cryptoencoder"))

  # Perturb column 'a' only
  d2 <- d
  d2$a <- d2$a + 100
  res2 <- anonymize_data(d2, key, opts = list(method = "cryptoencoder"))

  # ALL output columns should change (not just one)
  for (col in names(res$data)) {
    expect_false(identical(res$data[[col]], res2$data[[col]]),
                 info = paste("Column", col, "should differ after perturbing input"))
  }
})

test_that("no output column is a simple function of a single input column", {
  key <- key_from_passphrase("no-simple")
  set.seed(42)
  d <- data.frame(x = rnorm(100), y = rnorm(100), z = rnorm(100))
  res <- anonymize_data(d, key, opts = list(method = "cryptoencoder"))

  # Each output column should correlate with MULTIPLE input columns,
  # not just one. Check that no output column has |cor| > 0.99 with
  # any single input column.
  for (anon_col in names(res$data)) {
    cors <- sapply(d, function(x) abs(cor(x, res$data[[anon_col]])))
    expect_true(all(cors < 0.99),
                info = paste(anon_col, "has too-high correlation with an input column"))
  }
})

# ---------------------------------------------------------------------------
# Backward compatibility
# ---------------------------------------------------------------------------

test_that("default opts uses PCA method (backward compatible)", {
  key <- generate_key()
  res <- anonymize_data(sample_data, key)
  expect_equal(res$mapping$method, "pca")
  # PCA still drops a column
  expect_equal(ncol(res$data), ncol(sample_data) - 1L)
})

test_that("method validation rejects invalid methods", {
  key <- generate_key()
  expect_error(
    anonymize_data(sample_data, key, opts = list(method = "invalid")),
    "opts\\$method"
  )
})

test_that("old method names are rejected", {
  key <- generate_key()
  expect_error(
    anonymize_data(sample_data, key, opts = list(method = "autoencoder")),
    "opts\\$method"
  )
  expect_error(
    anonymize_data(sample_data, key, opts = list(method = "crypto_encoder")),
    "opts\\$method"
  )
})
