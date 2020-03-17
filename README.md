# aws-cognito-jwt-verifier
A Lambda function verifies the integrity of a JSON Web Token (JWT) provided by Cognito User Pool.

## External Dependencies

- [`python-jose`](https://github.com/mpdavis/python-jose)

### How to install external dependencies?

- Creating a function deployment package by following the documentation [here](https://docs.aws.amazon.com/lambda/latest/dg/python-package.html#python-package-dependencies).
- Creating a Lambda layer by following the documentation [here](https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html#configuration-layers-path).
- Install the “`native-python`” option mentioned in the documentation of `python-jose`: `pip install python-jose`.

## Internal Dependencies

The following libraries are included in AWS Lambda Python runtimes:

- `json`
- `logging`
- `base64`
- `time`
- `urllib`

## Example Lambda Event

```
{
  "token": ""
}
```

All parameters are compulsory to calculate a secret hash.

`token`: The JWT received from Cognito user pool. It can be either the access token or the ID token.

## Example Lambda Response

```
{
  "statusCode": 200,
  "body": {
    "header": {
      ...
    },
    "payload": {
      ...
    },
    "signatureValid": true,
    "notExpired": true,
    "matchingKeyFound": true
  }
}
```

The decoded JWT is stored in `header` and `payload` inside `body`.

`signatureValid` indicates if the JWT signature is verified.

`notExpired` indicates if the JWT is expired.

`matchingKeyFound` indicates if the `kid` supplied by the JWT header exists on the JWKs stored in `.well-known/jwks.json`.

This Lambda function is only capable of verifying the signature of a JWT against the issuer (`iss` in [JWT claim](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html)) supplied in the JWT.

Verifying signature, token use, scope against custom parameters is planned to be supported.

## Logging

If the Lambda function has the following permission, it will send diagnostic logs to CloudWatch log:

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "logs:CreateLogGroup",
            "Resource": "arn:aws:logs:<region>:<account-id>:*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": [
                "arn:aws:logs:<region>:<account-id>:log-group:/aws/lambda/<lambda-function-name>:*"
            ]
        }
    ]
}
```

Lambda function created as of today will automatically generate an execution role with this IAM policy attached.

### Notice

Since this Lambda function requires sensitive information such as the pair of client ID and client secret, the default logging level is set as `logging.ERROR`. Therefore, the function payload is not sent to CloudWatch automatically. Only the error message is forwarded to CloudWatch logs.