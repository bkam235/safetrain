# Generate sample_data for safetrain package
set.seed(42)
n <- 1000L
sample_data <- data.frame(
  user_id = paste0("U", sprintf("%05d", seq_len(n))),
  region = factor(sample(c("North", "South", "East", "West"), n, replace = TRUE),
                  levels = c("North", "South", "East", "West")),
  product = sample(c("A", "B", "C", "D", "E"), n, replace = TRUE),
  amount = round(runif(n, 10, 500), 2),
  count = sample(1L:20L, n, replace = TRUE),
  date = as.Date("2020-01-01") + sample(0:730, n, replace = TRUE),
  stringsAsFactors = FALSE
)
save(sample_data, file = "data/sample_data.rda", version = 2)
