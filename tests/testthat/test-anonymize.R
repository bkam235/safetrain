test_that("anonymize_data returns data and mapping", {
  d <- data.frame(a = 1:5, b = letters[1:5])
  key <- generate_key()
  res <- anonymize_data(d, key)
  expect_named(res, c("data", "mapping"))
  expect_s3_class(res$data, "data.frame")
  expect_equal(nrow(res$data), 5)
  # 2 columns anonymized -> 1 output column (one dropped)
  expect_equal(ncol(res$data), 1)
  expect_true(is.list(res$mapping))
  expect_true("columns" %in% names(res$mapping))
  expect_equal(res$mapping$version, 2L)
})

test_that("anonymize_data with columns subset only anonymizes those", {
  d <- data.frame(id = 1:3, x = c("A", "B", "A"), y = 10:12)
  key <- generate_key()
  # Anonymize 2 columns -> drops 1, so output has id + 1 anon col = 2
  res <- anonymize_data(d, key, columns = c("x", "y"))
  expect_equal(res$data$id, d$id)
  expect_equal(ncol(res$data), 2)
  expect_true("anon_1" %in% names(res$data))
  expect_equal(res$mapping$columns, c("x", "y"))
})

test_that("anonymize_data with passphrase works", {
  d <- data.frame(x = c("foo", "bar"), y = 1:2)
  res <- anonymize_data(d, "my-secret-passphrase")
  expect_named(res, c("data", "mapping"))
  # 2 columns -> 1 output
  expect_equal(ncol(res$data), 1)
})

test_that("anonymize_data is deterministic for same key", {
  d <- data.frame(x = c("A", "B", "A"), y = 1:3)
  key <- generate_key()
  r1 <- anonymize_data(d, key)
  r2 <- anonymize_data(d, key)
  expect_equal(r1$data$anon_1, r2$data$anon_1)
})

test_that("anonymized output column names are anon_*", {
  d <- data.frame(x = 1:5, y = 6:10)
  res <- anonymize_data(d, generate_key())
  expect_false(identical(names(res$data), names(d)))
  expect_true("anon_1" %in% names(res$data))
})

test_that("single-column anonymization does not drop", {
  d <- data.frame(id = 1:3, x = c("A", "B", "A"))
  key <- generate_key()
  res <- anonymize_data(d, key, columns = "x")
  # 1 column anonymized -> no drop, output has id + anon_1 = 2 cols
  expect_equal(ncol(res$data), 2)
  expect_equal(res$data$id, d$id)
  expect_true("anon_1" %in% names(res$data))
})
