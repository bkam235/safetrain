test_that("encode/decode round-trip for numeric", {
  x <- c(1.5, 2.7, 3.9, NA)
  enc <- encode_column(x)
  expect_equal(enc$type, "numeric")
  dec <- decode_column(enc$values, enc)
  expect_equal(dec, x)
})

test_that("encode/decode round-trip for integer", {
  x <- c(1L, 5L, 10L, NA)
  enc <- encode_column(x)
  expect_equal(enc$type, "integer")
  dec <- decode_column(enc$values, enc)
  expect_equal(dec, x)
})

test_that("encode/decode round-trip for character", {
  x <- c("apple", "banana", "apple", NA)
  enc <- encode_column(x)
  expect_equal(enc$type, "categorical")
  dec <- decode_column(enc$values, enc)
  expect_equal(dec, x)
})

test_that("encode/decode round-trip for factor", {
  x <- factor(c("X", "Y", "X", NA), levels = c("X", "Y", "Z"))
  enc <- encode_column(x)
  expect_equal(enc$type, "factor")
  dec <- decode_column(enc$values, enc)
  expect_equal(levels(dec), levels(x))
  expect_equal(as.character(dec), as.character(x))
  expect_true(is.na(dec[4]))
})

test_that("encode/decode round-trip for Date", {
  x <- as.Date(c("2020-01-01", "2021-06-15", NA))
  enc <- encode_column(x)
  expect_equal(enc$type, "date")
  dec <- decode_column(enc$values, enc)
  expect_equal(dec[1:2], x[1:2])
  expect_true(is.na(dec[3]))
})

test_that("encode/decode round-trip for POSIXt", {
  x <- as.POSIXct(c("2020-01-01 12:00:00", "2021-06-15 08:30:00", NA), tz = "UTC")
  enc <- encode_column(x)
  expect_equal(enc$type, "datetime")
  dec <- decode_column(enc$values, enc)
  expect_equal(as.numeric(dec[1:2]), as.numeric(x[1:2]))
  expect_true(is.na(dec[3]))
})

test_that("encode/decode round-trip for logical", {
  x <- c(TRUE, FALSE, TRUE, NA)
  enc <- encode_column(x)
  expect_equal(enc$type, "categorical")
  dec <- decode_column(enc$values, enc)
  expect_equal(dec[1:3], as.character(x[1:3]))
  expect_true(is.na(dec[4]))
})

test_that("encode produces 0-indexed codes for categorical", {
  x <- c("B", "A", "C", "A")
  enc <- encode_column(x)
  # Sorted unique: A=0, B=1, C=2
  expect_equal(enc$values, c(1, 0, 2, 0))
  expect_equal(enc$labels, c("A", "B", "C"))
})

test_that("decode clamps out-of-range codes", {
  enc <- list(type = "categorical", labels = c("A", "B", "C"), levels_orig = NULL)
  # Code -1 should clamp to label 1 ("A"), code 5 should clamp to label 3 ("C")
  dec <- decode_column(c(-1, 5), enc)
  expect_equal(dec, c("A", "C"))
})
