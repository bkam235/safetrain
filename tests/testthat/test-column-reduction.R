test_that("all columns anonymized: output has n-1 columns", {
  d <- data.frame(a = 1:5, b = 6:10, c = 11:15)
  key <- generate_key()
  res <- anonymize_data(d, key)
  expect_equal(ncol(res$data), 2)
  expect_equal(names(res$data), c("anon_1", "anon_2"))
})

test_that("partial anonymization (2 selected): output has total-1 columns", {
  d <- data.frame(id = 1:5, x = 6:10, y = 11:15)
  key <- generate_key()
  res <- anonymize_data(d, key, columns = c("x", "y"))
  # id (not anonymized) + 1 anon col = 2
  expect_equal(ncol(res$data), 2)
  expect_true("id" %in% names(res$data))
  expect_true("anon_1" %in% names(res$data))
})

test_that("single column anonymized: no column drop", {
  d <- data.frame(id = 1:5, val = 6:10)
  key <- generate_key()
  res <- anonymize_data(d, key, columns = "val")
  # id + anon_1 = 2 columns (same as original)
  expect_equal(ncol(res$data), 2)
})

test_that("6-column dataframe produces 5 anonymized columns", {
  d <- data.frame(
    a = 1:10, b = 11:20, c = 21:30,
    d = 31:40, e = 41:50, f = 51:60
  )
  key <- generate_key()
  res <- anonymize_data(d, key)
  expect_equal(ncol(res$data), 5)
  expect_equal(names(res$data), paste0("anon_", 1:5))
})

test_that("zero columns selected returns original data unchanged", {
  d <- data.frame(x = 1:3, y = 4:6)
  key <- generate_key()
  res <- anonymize_data(d, key, columns = character(0))
  expect_equal(res$data, d)
})

test_that("round-trip preserves row count through column reduction", {
  d <- data.frame(a = 1:100, b = runif(100), c = letters[rep(1:10, 10)])
  key <- generate_key()
  res <- anonymize_data(d, key)
  expect_equal(nrow(res$data), 100)
  back <- deanonymize_data(res$data, key, res$mapping)
  expect_equal(nrow(back), 100)
})
