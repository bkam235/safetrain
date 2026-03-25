test_that("different keys produce different anonymized output", {
  d <- data.frame(x = 1:5, y = letters[1:5], z = runif(5))
  k1 <- key_from_passphrase("key-alpha")
  k2 <- key_from_passphrase("key-beta")
  r1 <- anonymize_data(d, k1)
  r2 <- anonymize_data(d, k2)
  expect_false(identical(r1$data, r2$data))
})

test_that("deanonymization with wrong key does not recover original", {
  d <- data.frame(x = 1:10, y = runif(10))
  k1 <- key_from_passphrase("correct-key")
  k2 <- key_from_passphrase("wrong-key")
  res <- anonymize_data(d, k1)
  back_wrong <- suppressWarnings(deanonymize_data(res$data, k2, res$mapping))
  # Values should differ substantially
  expect_false(isTRUE(all.equal(back_wrong$x, d$x, tolerance = 0.1)))
})

test_that("deanonymization with wrong key does not crash", {
  d <- data.frame(a = 1:5, b = letters[1:5])
  k1 <- key_from_passphrase("right")
  k2 <- key_from_passphrase("wrong")
  res <- anonymize_data(d, k1)
  # Should not error, just produce garbage
  expect_no_error(suppressWarnings(deanonymize_data(res$data, k2, res$mapping)))
})

test_that("mapping alone is insufficient for reversal", {
  d <- data.frame(x = 1:10, y = runif(10))
  key <- key_from_passphrase("secret")
  res <- anonymize_data(d, key)
  # The mapping does not contain the rotation matrix or center/scale.
  # Only encrypted_dropped, col_names, and n_original_cols.
  expect_null(res$mapping$pca$rotation)
  expect_null(res$mapping$pca$center)
  expect_null(res$mapping$pca$scale)
  # encrypted_dropped is raw bytes, not the plain values
  expect_type(res$mapping$pca$encrypted_dropped, "raw")
})
