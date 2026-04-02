library(safetrain)

test_that("DP noise changes output values", {
  key <- generate_key()
  data(sample_data)
  X <- sample_data[, c("amount", "count", "user_id")]

  set.seed(1); res_no_dp <- anonymize_data(X, key,
                              opts = list(method = "cryptoencoder"))
  set.seed(1); res_dp    <- anonymize_data(X, key,
                              opts = list(method = "cryptoencoder",
                                          dp_epsilon = 1.0))
  expect_false(identical(res_no_dp$data, res_dp$data))
})

test_that("DP parameters are recorded in the mapping", {
  key <- generate_key()
  data(sample_data)
  X <- sample_data[, c("amount", "count")]
  res <- anonymize_data(X, key,
                        opts = list(method = "cryptoencoder",
                                    dp_epsilon = 0.5, dp_delta = 1e-6))
  expect_equal(res$mapping$pca$dp_epsilon, 0.5)
  expect_equal(res$mapping$pca$dp_delta,   1e-6)
  expect_true(res$mapping$pca$dp_sigma > 0)
})

test_that("halving epsilon doubles sigma", {
  key <- generate_key()
  data(sample_data)
  X <- sample_data[, c("amount", "count", "user_id")]
  r1 <- anonymize_data(X, key, opts = list(method = "cryptoencoder",
                                            dp_epsilon = 1.0))
  r2 <- anonymize_data(X, key, opts = list(method = "cryptoencoder",
                                            dp_epsilon = 0.5))
  expect_equal(r2$mapping$pca$dp_sigma / r1$mapping$pca$dp_sigma, 2,
               tolerance = 1e-10)
})

test_that("sigma formula is correct: 2*sqrt(n)*sqrt(2*log(1.25/delta))/eps", {
  key <- generate_key()
  data(sample_data)
  X <- sample_data[, c("amount", "count", "user_id")]  # 3 cols -> n = 3
  eps <- 1.0; delta <- 1e-5
  res <- anonymize_data(X, key,
                        opts = list(method = "cryptoencoder",
                                    dp_epsilon = eps, dp_delta = delta))
  n <- ncol(res$data)
  expected_sigma <- 2 * sqrt(n) * sqrt(2 * log(1.25 / delta)) / eps
  expect_equal(res$mapping$pca$dp_sigma, expected_sigma, tolerance = 1e-10)
})

test_that("DP with method = 'pca' raises an informative error", {
  key <- generate_key()
  data(sample_data)
  expect_error(
    anonymize_data(sample_data, key,
                   opts = list(method = "pca", dp_epsilon = 1.0)),
    "only supported for method.*cryptoencoder"
  )
})

test_that("invalid dp_epsilon values raise errors", {
  key <- generate_key()
  data(sample_data)
  X <- sample_data[, c("amount", "count")]
  expect_error(
    anonymize_data(X, key, opts = list(method = "cryptoencoder",
                                        dp_epsilon = -1)),
    "positive"
  )
  expect_error(
    anonymize_data(X, key, opts = list(method = "cryptoencoder",
                                        dp_epsilon = 0)),
    "positive"
  )
  expect_error(
    anonymize_data(X, key, opts = list(method = "cryptoencoder",
                                        dp_epsilon = 1.0, dp_delta = 1.5)),
    "\\(0, 1\\)"
  )
})

test_that("deanonymize_data does not error with a DP mapping", {
  # Recovery won't match original (noise is irrecoverable) but must not error.
  key <- generate_key()
  data(sample_data)
  X <- sample_data[, c("amount", "count")]
  res <- anonymize_data(X, key,
                        opts = list(method = "cryptoencoder",
                                    dp_epsilon = 1.0))
  expect_error(deanonymize_data(res$data, key, res$mapping), NA)
})

test_that("no DP noise when dp_epsilon is NULL (default)", {
  key <- generate_key()
  data(sample_data)
  X <- sample_data[, c("amount", "count")]
  res <- anonymize_data(X, key, opts = list(method = "cryptoencoder"))
  expect_null(res$mapping$pca$dp_epsilon)
  expect_null(res$mapping$pca$dp_sigma)
})
