import boto3
import json
import logging
import os
import base64
import urllib.parse
import urllib.request
import urllib.error
from typing import Dict, Any

# Set up logging
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger()

# Constants
DATA_BUCKET = os.environ['DATA_BUCKET']
SECRET_NAME = os.environ['SECRET_NAME']
S3_CLIENT = boto3.client('s3')

ENVIRONMENT = 'sandbox' if DATA_BUCKET == 'tag-dl-sandbox-data' else 'production'
ID = 'JOB_ID'

class RequestError(Exception):
    def __init__(self, status_code, reason, message, request_info):
        super().__init__(message)
        self.status_code = status_code
        self.reason = reason
        self.message = message
        self.request_info = request_info


def make_request(url: str, request_type: str, is_binary=False, **kwargs) -> Dict[str, Any]:

    headers = kwargs.get('headers', {})

    if 'params' in kwargs:
        url += '?' + urllib.parse.urlencode(kwargs['params'])

    data = None
    if 'json' in kwargs:
        headers['Content-Type'] = 'application/json'
        data = json.dumps(kwargs['json']).encode('utf-8')
    elif 'data' in kwargs:
        data = kwargs['data'].encode('utf-8')

    req = urllib.request.Request(url, data=data, headers=headers, method=request_type)

    request_info = {
        'url': url,
        'request_type': request_type,
        'headers': headers,
        'data': data
    }

    try:
        with urllib.request.urlopen(req) as response:
            content = response.read()
            status_code = response.getcode()

            if status_code == 204:
                return {'status_code': 204, 'message': 'No content'}
            elif is_binary:
                return content
            else:
                try:
                    return json.loads(content.decode())
                except Exception:
                    return {'message': 'Received non-JSON response', 'status_code': status_code}

    except urllib.error.HTTPError as e:
        raise RequestError(
            status_code=e.code,
            reason=e.reason,
            message=e.read().decode(),
            request_info=request_info
        )

def get_credentials(secret_manager_client: 'botocore.client.SecretsManager',
                    secret_name: str) -> Dict[str, Any]:
    """
    Decrypts secret stored in AWS Secrets Manager by using the secret-name's associated KMS key.
    Depending on whether the secret is a string or binary, a Dict is returned.

    :param secret_manager_client: botocore.client.SecretsManager - SecretsManager client instance
    :param secret_name: - Name of the secret as saved in AWS
    :return: Dict[str, object] - Dict containing object stores in SecretsManager
    """

    secret_response = secret_manager_client.get_secret_value(SecretId=secret_name)

    if 'SecretString' in secret_response:
        secret = secret_response['SecretString']
        return json.loads(secret)
    else:
        decoded_binary_secret = base64.b64decode(secret_response['SecretBinary'])
        return json.loads(decoded_binary_secret)

def get_json_file_from_s3(s3_client, bucket: str, key: str) -> Dict[str, Any]:
    try:
        response = s3_client.get_object(Bucket=bucket, Key=key)
        return json.loads(response['Body'].read())  # File is good
    except Exception as e:
        logger.error(f'Error while getting file from S3: {e}')
        raise e  # File is not good

def check_data(data: Dict[str, Any]) -> bool:
    if len(data) == 1:
        return True
    else:
        logger.error(f'Data length is {len(data)}. Expected length equal to 12')
        return False

def prepare_data(job_id_json_file: Dict[str, Any]) ->str:
    return job_id_json_file['TAG_JOB_ID_NAME']

def send_data_to_bizaway(job_id_value: str, environment, custom_field_id) -> Dict[str, Any]:


    bizaway_url = f"https://{environment}.bizaway.io/custom-fields/{custom_field_id}/values"
    method = 'POST'
    data_body = {
        "value": job_id_value
    }
    headers = {
        'Authorization': f'Bearer {access_token_value}',
        'Content-Type': 'application/json',
        'Accept-Encoding': 'gzip',
        'API-Version': '1.1'
    }

    response = make_request(
        url=bizaway_url,
        request_type=method,
        headers=headers,
        json=data_body
    )

    return response



# Constants
DATA_BUCKET = os.environ['DATA_BUCKET']
SECRET_NAME = os.environ['SECRET_NAME']
S3_CLIENT = boto3.client('s3')
SECRET_MANAGER_CLIENT = boto3.client('secretsmanager')

access_token_value = get_credentials(
    secret_manager_client=SECRET_MANAGER_CLIENT, secret_name=SECRET_NAME
)['access_token']



def main(event, context):
    logger.info(f'Event: {event}')
    key = event['Records'][0]['s3']['object']['key']
    try:
        job_id_json_file = get_json_file_from_s3(s3_client=S3_CLIENT, bucket=DATA_BUCKET, key=key)
        job_id_value = prepare_data(job_id_json_file)

        response = send_data_to_bizaway(
            job_id_value=job_id_value,
            environment=ENVIRONMENT,
            custom_field_id=ID
        )
        logger.info(response)

        return response
    except Exception as e:
        logger.info(f'Error: {e}')
        return {
            'status': 'error',
            'message': 'Data is not good. Exiting the process. Probably the file is not the one containing only 1 job id'
        
        }








    


#step_1 = read from s3---> DONE
#step 2 = check if it is good--> DONE
#step 3 = prepare the data--> HOW I PREPARE THE DATA? WHICH ARE THE REQUIREMENTS?
#step 4 = send the data--> WHERE?

