import json
import boto3
boto3.setup_default_session(region_name='us-east-1') 
from botocore.exceptions import ClientError

cognito_client = boto3.client('cognito-idp')

USER_POOL_ID = 'us-east-1_3RzbSvzQU'
CLIENT_ID = '1qlrfcahr8adusjngigqfuieip'

#verifica CPF
def verify_cpf_format(cpf: str) -> bool:
    return len(cpf) == 11 and cpf.isdigit()

def lambda_handler(event, context):
    print(event)
    req_body = event['body']
    print(req_body)
    json_acceptable_string = req_body.replace("'", "\"")
    d = json.loads(json_acceptable_string)
    user = d.get("cpf")
    pwd = d.get("password")
    email = d.get("email")

    if not user or not pwd:
        return {
            "statusCode": 400,
            "body": json.dumps({"message": "CPF e/ou senha não fornecidos."})
        }
    
    if not email:
        return {
            "statusCode": 400,
            "body": json.dumps({"message": "E-mail deve ser preenchido."})
        }
    
    if not verify_cpf_format(user):
        return {
            "statusCode": 400,
            "body": json.dumps({"message": "CPF inválido!"})
        }

    try:
        response = cognito_client.initiate_auth(
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': user,
                'PASSWORD': pwd
            },
            ClientId=CLIENT_ID
        )
        challenge = response.get('ChallengeName')

        if challenge == 'NEW_PASSWORD_REQUIRED':
            challenge_response = cognito_client.respond_to_auth_challenge(
                ClientId=CLIENT_ID,
                ChallengeName='NEW_PASSWORD_REQUIRED',
                Session=response.get('Session'),
                ChallengeResponses={
                    'USERNAME': user,
                    'NEW_PASSWORD': pwd
                }
            )
            token = challenge_response.get("AuthenticationResult", {}).get("AccessToken")
        else:
            token = response.get("AuthenticationResult", {}).get("AccessToken")

        return {
            "statusCode": 200,
            "body": json.dumps({"token": token})
        }
    except ClientError as e:
        return {
            "statusCode": 400,
            "body": json.dumps({"message": str(e)})
        }