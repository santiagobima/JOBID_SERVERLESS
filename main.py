import boto3
import json
import logging
from typing import Dict, Any

# Set up logging
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger()

# Constants
DATA_BUCKET = 'tag-dl-sandbox-data'
SECRET_MANAGER_CLIENT = boto3.client('secretsmanager', region_name='eu-west-1')
S3_CLIENT = boto3.client('s3', region_name='eu-west-1')

def get_json_file_from_s3(s3_client, bucket: str, key: str) -> Dict[str, Any]:
    try:
        response = s3_client.get_object(Bucket=bucket, Key=key)
        return json.loads(response['Body'].read())
    except Exception as e:
        logger.error(f'Error while getting file from S3: {e}')
        raise e

def check_data(data: Dict[str, Any]) -> bool:
    if len(data) == 12:
        return True
    else:
        logger.error(f'Data length is {len(data)}. Expected length equal to 12')
        return False

def prepare_data(job_id_json_file: Dict[str, Any]) -> Dict[str, Any]:
    return job_id_json_file

def send_data_to_bizaway(data: Dict[str, Any]) -> Dict[str, Any]:
    response = {
        'status': 'success',
        'message': 'Data has been sent to BizAway'
    }
    return response

def main(event, context) -> bool:
    key = event['Records'][0]['s3']['object']['key']
    try:
        job_id_json_file = get_json_file_from_s3(s3_client=S3_CLIENT, bucket=DATA_BUCKET, key=key)

        if check_data(job_id_json_file):
            print('Data is good. Proceeding to the next step')
            prepared_data = prepare_data(job_id_json_file)
            response = send_data_to_bizaway(prepared_data)
            print(response)
            return True
        else:
            print('Data is not good. Exiting the process.')
            return False
    except Exception as e:
        logger.error(f'Error while processing the data: {e}')
        return False

if __name__ == "__main__":
    # Simulate an S3 event
    event = {
        'Records': [
            {
                's3': {
                    'bucket': {
                        'name': DATA_BUCKET
                    },
                    'object': {
                        'key': 'intake/transition/job_id_services/TAG_JOB_ID/your_test_file.json'
                    }
                }
            }
        ]
    }
    context = None  # 
    main(event, context)






    


#step_1 = read from s3---> DONE
#step 2 = check if it is good--> DONE
#step 3 = prepare the data--> HOW I PREPARE THE DATA? WHICH ARE THE REQUIREMENTS?
#step 4 = send the data--> WHERE?

