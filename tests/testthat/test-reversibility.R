test_that("round-trip recovers original data", {
  d <- data.frame(
    id = 1:10,
    cat = letters[1:10],
    num = runif(10)
  )
  key <- generate_key()
  res <- anonymize_data(d, key)
  back <- deanonymize_data(res$data, key, res$mapping)
  expect_equal(back$id, d$id)
  expect_equal(back$cat, d$cat)
  expect_equal(back$num, d$num, tolerance = 1e-8)
})

test_that("round-trip works with factors", {
  d <- data.frame(
    f = factor(c("X", "Y", "X", "Z"), levels = c("X", "Y", "Z")),
    g = 1:4
  )
  key <- generate_key()
  res <- anonymize_data(d, key)
  back <- deanonymize_data(res$data, key, res$mapping)
  expect_equal(levels(back$f), levels(d$f))
  expect_equal(as.character(back$f), as.character(d$f))
  expect_equal(back$g, d$g)
})

test_that("round-trip works with Dates", {
  d <- data.frame(
    dt = as.Date(c("2020-01-01", "2021-06-15")),
    val = c(10.5, 20.3)
  )
  key <- generate_key()
  res <- anonymize_data(d, key)
  back <- deanonymize_data(res$data, key, res$mapping)
  expect_equal(back$dt, d$dt)
  expect_equal(back$val, d$val, tolerance = 1e-8)
})

test_that("round-trip works with sample_data", {
  key <- generate_key()
  res <- anonymize_data(sample_data, key)
  back <- deanonymize_data(res$data, key, res$mapping)
  expect_equal(back$user_id, sample_data$user_id)
  expect_equal(back$region, sample_data$region)
  expect_equal(back$product, sample_data$product)
  expect_equal(back$amount, sample_data$amount, tolerance = 1e-8)
  expect_equal(back$count, sample_data$count)
  expect_equal(back$date, sample_data$date)
})

test_that("round-trip with partial columns (2+ selected)", {
  d <- data.frame(a = 1:5, b = letters[1:5], c = runif(5))
  key <- generate_key()
  res <- anonymize_data(d, key, columns = c("b", "c"))
  back <- deanonymize_data(res$data, key, res$mapping)
  expect_equal(back$a, d$a)
  expect_equal(back$b, d$b)
  expect_equal(back$c, d$c, tolerance = 1e-8)
})

test_that("round-trip with single partial column", {
  d <- data.frame(a = 1:5, b = letters[1:5], c = runif(5))
  key <- generate_key()
  res <- anonymize_data(d, key, columns = "b")
  back <- deanonymize_data(res$data, key, res$mapping)
  expect_equal(back$a, d$a)
  expect_equal(back$b, d$b)
  expect_equal(back$c, d$c)
})
