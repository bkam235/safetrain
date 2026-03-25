test_that("generate_key returns raw vector of correct length", {
  k <- generate_key()
  expect_type(k, "raw")
  expect_length(k, 32)
})

test_that("generate_key respects bytes argument", {
  k <- generate_key(16)
  expect_length(k, 16)
})

test_that("generate_key rejects < 16 bytes", {
  expect_error(generate_key(8), "at least 16 bytes")
})

test_that("key_from_passphrase is deterministic", {
  k1 <- key_from_passphrase("test-phrase")
  k2 <- key_from_passphrase("test-phrase")
  expect_identical(k1, k2)
})

test_that("key_from_passphrase returns 32 raw bytes", {
  k <- key_from_passphrase("hello")
  expect_type(k, "raw")
  expect_length(k, 32)
})

test_that("different passphrases produce different keys", {
  k1 <- key_from_passphrase("alpha")
  k2 <- key_from_passphrase("beta")
  expect_false(identical(k1, k2))
})

test_that("normalize_key returns raw input as-is", {
  k <- generate_key()
  expect_identical(normalize_key(k), k)
})

test_that("normalize_key converts character to key", {
  k <- normalize_key("my-passphrase")
  expect_type(k, "raw")
  expect_length(k, 32)
  expect_identical(k, key_from_passphrase("my-passphrase"))
})

test_that("normalize_key rejects invalid input", {
  expect_error(normalize_key(42), "key must be raw bytes")
  expect_error(normalize_key(c("a", "b")), "key must be raw bytes")
})

test_that("derive_column_key is deterministic", {
  k <- generate_key()
  c1 <- derive_column_key(k, "col_a")
  c2 <- derive_column_key(k, "col_a")
  expect_identical(c1, c2)
})

test_that("derive_column_key differs for different columns", {
  k <- generate_key()
  c1 <- derive_column_key(k, "col_a")
  c2 <- derive_column_key(k, "col_b")
  expect_false(identical(c1, c2))
})

test_that("derive_column_key differs for different master keys", {
  k1 <- key_from_passphrase("key1")
  k2 <- key_from_passphrase("key2")
  c1 <- derive_column_key(k1, "col")
  c2 <- derive_column_key(k2, "col")
  expect_false(identical(c1, c2))
})

test_that("hmac_prng_stream is deterministic", {
  k <- key_from_passphrase("seed")
  s1 <- hmac_prng_stream(k, "label", 64)
  s2 <- hmac_prng_stream(k, "label", 64)
  expect_identical(s1, s2)
})

test_that("hmac_prng_stream returns correct length", {
  k <- key_from_passphrase("seed")
  s <- hmac_prng_stream(k, "test", 100)
  expect_type(s, "raw")
  expect_length(s, 100)
})

test_that("hmac_prng_stream differs for different labels", {
  k <- key_from_passphrase("seed")
  s1 <- hmac_prng_stream(k, "label-a", 32)
  s2 <- hmac_prng_stream(k, "label-b", 32)
  expect_false(identical(s1, s2))
})

test_that("hmac_prng_stream differs for different keys", {
  k1 <- key_from_passphrase("key1")
  k2 <- key_from_passphrase("key2")
  s1 <- hmac_prng_stream(k1, "label", 32)
  s2 <- hmac_prng_stream(k2, "label", 32)
  expect_false(identical(s1, s2))
})
