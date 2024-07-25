import unittest
from unittest.mock import patch, MagicMock
import json
from lambda_function import lambda_handler, verify_cpf_format

class TestLambdaFunction(unittest.TestCase):

    def setUp(self):
        self.context = {}

    def test_verify_cpf_format_valid(self):
        self.assertTrue(verify_cpf_format("12345678901"))

    def test_verify_cpf_format_invalid(self):
        self.assertFalse(verify_cpf_format("1234567890a"))
        self.assertFalse(verify_cpf_format("1234567890"))

    @patch('lambda_function.cognito_client')
    def test_lambda_handler_missing_cpf(self, mock_cognito_client):
        event = {
            "body": json.dumps({"password": "Password123", "email": "test@example.com"})
        }
        response = lambda_handler(event, self.context)
        self.assertEqual(response["statusCode"], 400)
        self.assertIn("CPF e/ou senha n\\u00e3o fornecidos", response["body"])

    @patch('lambda_function.cognito_client')
    def test_lambda_handler_missing_email(self, mock_cognito_client):
        event = {
            "body": json.dumps({"cpf": "12345678901", "password": "Password123"})
        }
        response = lambda_handler(event, self.context)
        self.assertEqual(response["statusCode"], 400)
        self.assertIn("E-mail deve ser preenchido", response["body"])

    @patch('lambda_function.cognito_client')
    def test_lambda_handler_invalid_cpf(self, mock_cognito_client):
        event = {
            "body": json.dumps({"cpf": "1234567890", "password": "Password123", "email": "test@example.com"})
        }
        response = lambda_handler(event, self.context)
        self.assertEqual(response["statusCode"], 400)
        self.assertIn("CPF inv\\u00e1lido!", response["body"])

    @patch('lambda_function.cognito_client')
    def test_lambda_handler_auth_success(self, mock_cognito_client):
        event = {
            "body": json.dumps({"cpf": "12345678901", "password": "Password123", "email": "test@example.com"})
        }
        mock_response = {
            "AuthenticationResult": {
                "AccessToken": "test_token"
            }
        }
        mock_cognito_client.initiate_auth.return_value = mock_response
        response = lambda_handler(event, self.context)
        self.assertEqual(response["statusCode"], 200)
        self.assertIn("token", response["body"])

    @patch('lambda_function.cognito_client')
    def test_lambda_handler_auth_challenge(self, mock_cognito_client):
        event = {
            "body": json.dumps({"cpf": "12345678901", "password": "Password123", "email": "test@example.com"})
        }
        mock_response = {
            "ChallengeName": "NEW_PASSWORD_REQUIRED",
            "Session": "test_session"
        }
        mock_challenge_response = {
            "AuthenticationResult": {
                "AccessToken": "test_token"
            }
        }
        mock_cognito_client.initiate_auth.return_value = mock_response
        mock_cognito_client.respond_to_auth_challenge.return_value = mock_challenge_response
        response = lambda_handler(event, self.context)
        self.assertEqual(response["statusCode"], 200)
        self.assertIn("token", response["body"])

if __name__ == '__main__':
    unittest.main()