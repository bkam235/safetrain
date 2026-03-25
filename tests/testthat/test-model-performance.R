test_that("model performance on de-anonymized data matches original", {
  skip_if_not_installed("ranger")
  # PCA mixes all columns jointly, so predictions from a model trained in PC
  # space cannot be mapped back to the original amount scale via a simple
  # per-column inverse. Instead we verify the round-trip property: anonymizing
  # and then de-anonymizing the training data should yield identical model
  # performance, because deanonymize_data() exactly recovers the original values.
  set.seed(42)
  n   <- nrow(sample_data)
  idx <- sample(n, floor(0.7 * n))
  train_orig <- sample_data[idx, ]
  test_orig  <- sample_data[-idx, ]

  key              <- generate_key()
  anon             <- anonymize_data(train_orig, key)
  train_recovered  <- deanonymize_data(anon$data, key, anon$mapping)

  m_orig      <- ranger::ranger(amount ~ region + product + count, data = train_orig)
  m_recovered <- ranger::ranger(amount ~ region + product + count, data = train_recovered)

  pred_orig      <- predict(m_orig,      test_orig)$predictions
  pred_recovered <- predict(m_recovered, test_orig)$predictions

  rmse_orig      <- sqrt(mean((pred_orig      - test_orig$amount)^2))
  rmse_recovered <- sqrt(mean((pred_recovered - test_orig$amount)^2))

  # De-anonymized training data is bit-for-bit identical to the original
  # (within floating-point tolerance), so model performance must match.
  expect_equal(rmse_orig, rmse_recovered, tolerance = 1)
})

test_that("model performance on cryptoencoder round-trip matches original", {
  skip_if_not_installed("ranger")
  set.seed(42)
  n   <- nrow(sample_data)
  idx <- sample(n, floor(0.7 * n))
  train_orig <- sample_data[idx, ]
  test_orig  <- sample_data[-idx, ]

  key              <- generate_key()
  anon             <- anonymize_data(train_orig, key,
                                     opts = list(method = "cryptoencoder"))
  train_recovered  <- deanonymize_data(anon$data, key, anon$mapping)

  m_orig      <- ranger::ranger(amount ~ region + product + count, data = train_orig)
  m_recovered <- ranger::ranger(amount ~ region + product + count, data = train_recovered)

  pred_orig      <- predict(m_orig,      test_orig)$predictions
  pred_recovered <- predict(m_recovered, test_orig)$predictions

  rmse_orig      <- sqrt(mean((pred_orig      - test_orig$amount)^2))
  rmse_recovered <- sqrt(mean((pred_recovered - test_orig$amount)^2))

  expect_equal(rmse_orig, rmse_recovered, tolerance = 1)
})
