# Over-privileged Lambda Execution Role
resource "aws_iam_role" "lambda_executor" {
  name = "lambda-data-processing-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
      }
    ]
  })
}

resource "aws_iam_policy" "wildcard_data_policy" {
  name        = "data-pipeline-wildcard-policy"
  description = "Excessive wildcard administrative privileges"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = ["*"]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}
