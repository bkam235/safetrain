library(safetrain)
library(caret)
library(data.table)
library(mlbench)

data("BostonHousing")

dt <- as.data.table(BostonHousing)

fit <- train(y = dt$medv,
             x = dt[, -"medv", with=F],
             method = "gbm")

dta <- anonymize_data(dt[, -"medv", with=F], key="123", 
                      opts=list(methods="cryptoencoder", ae_max_epochs=10000))
dtad <- as.data.table(dta$data)

fita <- train(y = dt$medv,
             x = dtad,
             method = "gbm")

