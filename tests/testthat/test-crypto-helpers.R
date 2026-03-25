test_that("generate_key_rotation produces orthogonal matrix", {
  key <- key_from_passphrase("test")
  Q <- generate_key_rotation(key, 5)
  expect_equal(dim(Q), c(5, 5))
  # Q^T Q should be identity
  expect_equal(t(Q) %*% Q, diag(5), tolerance = 1e-10)
})

test_that("generate_key_rotation is deterministic", {
  key <- key_from_passphrase("test")
  Q1 <- generate_key_rotation(key, 4)
  Q2 <- generate_key_rotation(key, 4)
  expect_identical(Q1, Q2)
})

test_that("generate_key_rotation differs for different keys", {
  k1 <- key_from_passphrase("key-alpha")
  k2 <- key_from_passphrase("key-beta")
  Q1 <- generate_key_rotation(k1, 3)
  Q2 <- generate_key_rotation(k2, 3)
  expect_false(identical(Q1, Q2))
})

test_that("generate_key_rotation works for n=1", {
  key <- key_from_passphrase("test")
  Q <- generate_key_rotation(key, 1)
  expect_equal(dim(Q), c(1, 1))
  # 1x1 orthogonal matrix is +1 or -1
  expect_equal(abs(Q[1, 1]), 1, tolerance = 1e-10)
})

test_that("derive_center_scale is deterministic", {
  key <- key_from_passphrase("test")
  cs1 <- derive_center_scale(key, c("a", "b", "c"))
  cs2 <- derive_center_scale(key, c("a", "b", "c"))
  expect_identical(cs1, cs2)
})

test_that("derive_center_scale differs for different keys", {
  k1 <- key_from_passphrase("key1")
  k2 <- key_from_passphrase("key2")
  cs1 <- derive_center_scale(k1, c("a", "b"))
  cs2 <- derive_center_scale(k2, c("a", "b"))
  expect_false(identical(cs1$center, cs2$center))
  expect_false(identical(cs1$scale, cs2$scale))
})

test_that("derive_center_scale values are in expected range", {
  key <- key_from_passphrase("test")
  cs <- derive_center_scale(key, c("a", "b", "c", "d", "e"))
  expect_true(all(cs$center >= -1000 & cs$center <= 1000))
  expect_true(all(cs$scale >= 0.5 & cs$scale <= 2.0))
})

test_that("encrypt/decrypt dropped column round-trip is exact", {
  key <- key_from_passphrase("test-encrypt")
  vals <- c(1.23456789, -999.999, 0, NA, Inf, -Inf)
  encrypted <- encrypt_dropped_column(vals, key)
  expect_type(encrypted, "raw")
  decrypted <- decrypt_dropped_column(encrypted, key)
  expect_identical(vals, decrypted)
})

test_that("encrypt with wrong key does not decrypt correctly", {
  k1 <- key_from_passphrase("right-key")
  k2 <- key_from_passphrase("wrong-key")
  vals <- c(1.5, 2.5, 3.5)
  encrypted <- encrypt_dropped_column(vals, k1)
  decrypted <- decrypt_dropped_column(encrypted, k2)
  expect_false(identical(vals, decrypted))
})

test_that("xor_raw is self-inverse", {
  a <- as.raw(c(0x00, 0xFF, 0xAB, 0x12))
  b <- as.raw(c(0x55, 0xAA, 0x01, 0xFE))
  result <- xor_raw(xor_raw(a, b), b)
  expect_identical(result, a)
})

test_that("bytes_to_uniforms returns values in (0, 1)", {
  raw_bytes <- as.raw(sample(0:255, 400, replace = TRUE))
  u <- bytes_to_uniforms(raw_bytes, 100)
  expect_length(u, 100)
  expect_true(all(u > 0 & u < 1))
})

test_that("box_muller produces standard-normal-like values", {
  # Generate enough values for a reasonable test
  set.seed(1)
  uniforms <- runif(2000)
  normals <- box_muller(uniforms)
  expect_length(normals, 2000)
  # Mean should be near 0, sd near 1
  expect_equal(mean(normals), 0, tolerance = 0.1)
  expect_equal(sd(normals), 1, tolerance = 0.1)
})

test_that("PCA transform/untransform round-trip with key", {
  key <- key_from_passphrase("roundtrip")
  mat <- matrix(c(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12), nrow = 4, ncol = 3)
  colnames(mat) <- c("a", "b", "c")

  res <- transform_numeric_pca(mat, key)
  # Output has one fewer column

  expect_equal(ncol(res$values), 2)
  expect_equal(nrow(res$values), 4)

  recovered <- untransform_numeric_pca(res$values, res$pca_info, key)
  expect_equal(recovered, mat, tolerance = 1e-10)
})

test_that("PCA transform single column (no drop)", {
  key <- key_from_passphrase("single")
  mat <- matrix(c(1, 2, 3, 4), nrow = 4, ncol = 1)
  colnames(mat) <- "x"

  res <- transform_numeric_pca(mat, key)
  expect_equal(ncol(res$values), 1)

  recovered <- untransform_numeric_pca(res$values, res$pca_info, key)
  expect_equal(recovered, mat, tolerance = 1e-10)
})

test_that("PCA transform with different keys gives different output", {
  k1 <- key_from_passphrase("key-one")
  k2 <- key_from_passphrase("key-two")
  mat <- matrix(1:12, nrow = 4, ncol = 3)
  colnames(mat) <- c("a", "b", "c")

  r1 <- transform_numeric_pca(mat, k1)
  r2 <- transform_numeric_pca(mat, k2)
  expect_false(identical(r1$values, r2$values))
})
