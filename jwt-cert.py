import json
import boto3
import os
import pprint
import ast
from time import sleep
import logging

logging_file = open("/tmp/myloggingfile.log", "w+")
# logging.basicConfig(level=logging.DEBUG, filename='/tmp/myloggingfile.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s')

logger = logging.getLogger()
logger.setLevel(logging.INFO)
f_handler = logging.FileHandler("/tmp/myloggingfile.log")
f_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
f_handler.setFormatter(f_format)
logger.addHandler(f_handler)


def lambda_handler(event, context):
    
    # TODO implement
    logger.info("LAMBDA HANDLER STARTED")
    creds = get_token()
    
    logger.info("TOKEN RECEIVED and SET")
    secret_list, client = fetch_all_secrets()
    
    logger.info("SECRETS RECEIVED AND GOING FOR UPDATE")
    update_secret(secret_list, client)
    
    logger.info("SECRETS UPDATED!!")
    return {
        'statusCode': 200,
        # 'body': json.dumps(response)
    }
    
def get_token():
    # create an STS client object that represents a live connection to the 
    # STS service
    sts_client = boto3.client('sts')
    # Call the assume_role method of the STSConnection object and pass the role
    # ARN and a role session name.
    assumed_role_object=sts_client.assume_role(
        RoleArn="arn:aws:iam::823368434544:role/aws-lambda-admin-access-cert-exp",
        RoleSessionName="mysession"
    )
    
    # From the response that contains the assumed role, get the temporary 
    # credentials that can be used to make subsequent API calls
    credentials=assumed_role_object['Credentials']
    logger.info(credentials)
    os.environ['AWS_ACCESS_KEY_ID']=credentials['AccessKeyId']
    os.environ['AWS_SECRET_ACCESS_KEY']=credentials['SecretAccessKey']
    os.environ['AWS_SESSION_TOKEN']=credentials['SessionToken']
    return credentials



def update_secret_to_fresh(d1,d2):
    logger.info("in update_secret_to_fresh")
    d1.update(d2)
    return d1

def fetch_all_secrets():
    client = boto3.client('secretsmanager')
    secret_list = []
    response = client.list_secrets(MaxResults=100)
    for item in response['SecretList']:
        secret_list.append([item['Name'],item['ARN']])
    logger.info(f"TOTAL SECRETS: {len(secret_list)}")
    return secret_list, client


def update_secret(secret_list, client):
    logger.info(secret_list[0])
    secret_versions = {}
    d1= {}
    d2 = {"SAMPLE_SECURITY_JWT_PUBLIC_KEY":r'-----BEGIN CERTIFICATE-----\nMIIECjCCAvKgAwIBAgIQEJCmDKEfWXZ2OAX3WkgehTANBgkqhkiG9w0BAQsFADB+\nMQswCQYDVQQGEwJOTDEQMA4GA1UECAwHVXRyZWNodDEOMAwGA1UEBwwFWmVpc3Qx\nFDASBgNVBAoMC1JhYm9iYW5rIE5MMRAwDgYDVQQLDAdSYWlsd2F5MSUwIwYDVQQD\nDBxSYWlsd2F5IE5vbiBQcm9kdWN0aW9uIENBIEcyMB4XDTIxMDMxNTEyNDMzMloX\nDTIyMDQxNTEzNDMzMlowLjEsMCoGA1UEAwwjand0LXRyYW5zbWl0LWRldi5wcm9q\nZWN0LXJhaWx3YXkubmwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC+\nJElhKl7VR+dNovkEeq5S2ikosh5bVHwdD7q0mGbt7uiGrBNRp+mTASZKOZUjw+Hd\nQXUMGpppMmcdpfW9zqX696aSq4n3fZegQvyx7rFiyjV413RYqKz8V2Mw6gJqR3CJ\nVwwd8jHt/eyxY8CxYSNg8ehOHs3LU7GPnbJt9wxih/xTlf5qnGbHN+7ZuA2THvXp\nc81FWxiJUbQrKkhPcaU0/ecoqTySyxfRG6XbHBuxI63RJSJu63x9PvqIwgqotpku\nQTKz3fCBGB0pyb/VGh/myaw2B87DdZngTNiFrdv05PRckq9KUZrp3EDtEIRHAo9j\nMrnhshCR9z5A95Bd3h9/AgMBAAGjgdMwgdAwVAYDVR0RBE0wS4Ikand0LXRyYW5z\nbWl0LXRlc3QucHJvamVjdC1yYWlsd2F5Lm5sgiNqd3QtdHJhbnNtaXQtZGV2LnBy\nb2plY3QtcmFpbHdheS5ubDAJBgNVHRMEAjAAMB8GA1UdIwQYMBaAFL10MBHwLk3y\nSc+TTaNFtcf/U9NSMB0GA1UdDgQWBBSCScjKmH2ZAr23GmfcxIcQk0KCbzAOBgNV\nHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMA0GCSqG\nSIb3DQEBCwUAA4IBAQCFbffMkWDivCFtjrWJJO/PgxOdKGDJzmAw0geG4RNWFAW0\nMj47AWyi8R8WPmXQBFnJc7R8YVLzrpjJubZ+WshK8SAbVtR5IJ+vNNIvF9FEO6F+\noNpWv15YcVqXlh0VU2UzOzWNAOCZiODPJFvS1zHzHEJ/EMHy5YvB96XNehe3Q8/L\nXQL5mY/lfktV9sP1m8E7/JdiMR2yKcdFEP2NYb3E1mc6+WuKkYq+5Pe2eExgNsbV\nlljSFIz4xK5Pz6otXGTONOVD4y683JxO0r+s90gUoWhqXFkbbx2mu664V4REzKgC\ngFGBJdM/dtLTcBLHEpfScMZaOuAWMz3ZKCX5iM/5\n-----END CERTIFICATE-----'}
    contents = ''
    file_contaning_jwt_cert = []
    file_not_cotaining_cert = []
    not_update_list = ["tcrns-slstr", "tqntm-scpsr", "msk-lambda-data-pipeline", "tnwhz-sanap", "tnwhz-samap", "tnwhz-sinap"]
    file_not_cotaining_cert.append({"MANUAL UPDATE": not_update_list})
    
    # Looping through Secrets and updating them 
    for sec_item in secret_list:
        try:
            
            key_length = 0
            
            # Create Condition for the invalid secrets i.e not_update_list
            if sec_item[0] not in not_update_list:
                
                # if sec_item[0]=='sample-secret-key3' or sec_item[0]=='sample-secret-key2' or sec_item[0]=='sample-secret-key':
                    
                ''' Getting the secret value '''
                secret_received = client.get_secret_value(SecretId=sec_item[1])
                
                logger.info(f"GETTING SECRET STRING \n\n {secret_received['SecretString']} \n\n")
                
                secret_string = secret_received['SecretString']
                
                # Converting the String to dict type
                d1 = ast.literal_eval(secret_string)
                
                key_length = len(d1.keys())
                
                logger.info(f"type of d1 : {type(d1)}")
                
                # fetched and ready to update ; CHECK THE DESIRED KEY IN SECRET
                # if 'SAMPLE_SECURITY_JWT_PUBLIC_KEY' in secret_received['SecretString']:
                    
                logger.info("KEY : RAILWAY_SECURITY_JWT_PUBLIC_KEY FOUND ... UPDATING...")
                
                # PUT YOUR KEY VALUE PAIR THAT NEEDS TO BE UPDATED
                # d1.update(SAMPLE_SECURITY_JWT_PUBLIC_KEY=r'-----BEGIN CERTIFICATE-----\nMIIEjjCCA3agAwIBAgIQa6mHezhUHjZSoQkujiBSvzANBgkqhkiG9w0BAQsFADCBh\ngzELMAkGA1UEBhMCTkwxEDAOBgNVBAgMB1V0cmVjaHQxEDAOBgNVBAcMB1V0cmVj\naHQxIzAhBgNVBAoMGkNvb3BlcmF0aWV2ZSBSYWJvYmFuayBVLkEuMSswKQYDVQQD\nDCJSYWJvYmFuayBPcGVuREFUQSBOb25Qcm9kdWN0aW9uIEcxMB4XDTIyMDQxMTEy\nNTkxN1oXDTIzMDUxMTEzNTkxN1owLjEsMCoGA1UEAwwjand0LXRyYW5zbWl0LWRl\ndi5wcm9qZWN0LXJhaWx3YXkubmwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\nAoIBAQCTbV2PKoqZ9z1oC3OIYzPCk0rLxwovg/AN29og2kbLrpdJD+5bfdQUVA2W\nl1+aGncnbZKjdC9ctn1CYNo9oIUC3qKyPo9ZUuaYYf7L3lOYZ43D30hZew+gW/4m\nUvTVgqHlWjHrxMDiOkoTU5eCeuTDG04jiAxumPFA2qdEkMKWgjqaTXxNt4Xi8OL/\nsEeu5kF6pIZWFgnztz6GGE3DhefY/afNrIhYrEzl+p2wzVph9KlsOqSoSDsquQCi\njT4I5sHW0SPzNe1NHJz0Wt7DBBORbbbWlExVKeZcgFMXGAFURmVmlh0GE22IBeMD\nwva7jYCIxlIjLs+fTScjKbeT4Pu1AgMBAAGjggFQMIIBTDBUBgNVHREETTBLgiRq\nd3QtdHJhbnNtaXQtdGVzdC5wcm9qZWN0LXJhaWx3YXkubmyCI2p3dC10cmFuc21p\ndC1kZXYucHJvamVjdC1yYWlsd2F5Lm5sMAkGA1UdEwQCMAAwHwYDVR0jBBgwFoAU\nmWH50DH+7O+w56N0pJedA9wn7oswHQYDVR0OBBYEFB99+FBqoUZJ3SB6xAjiYWRQ\nSKWcMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUH\nAwIwegYDVR0fBHMwcTBvoG2ga4ZpaHR0cDovL3JhaWx3YXktbm9ucHJvZC1jcmwt\nYnVja2V0LnMzLmV1LXdlc3QtMS5hbWF6b25hd3MuY29tL2NybC8xOTQ5NmNlOS01\nNzZjLTRiNjItODY3MS1jNGYzODZiNjk1YzIuY3JsMA0GCSqGSIb3DQEBCwUAA4IB\nAQBKb8Il5VrCXfU4xrRZBjcjylrlgCKqMAvhKAp+r1adYV1Sbqf0tw5ZhLwHJMUB\nAeDFcPmW64z1gufOgdEtD5GOuHyfIDephl0V0JUn+PCUHwZ6ohRn+xSIxLeYcdFx\nxptaC8ut9yrRx77E/K3rY4t6fLupXhFb0fYDvtsBG5ruvmSRMueN3O7G2f944lA1\nOUiB8ZGZ3m2oAmxjfMT4KC/oVC0DUfaoPOtO64+8eRjQMih8+6TErpl01zstfRV4\nTkFK3r55hAnG2go7zwf9KbyttugzVJa9Y7npln2AkRiH4nXNVXnn/r3BItAk2beN\n/WIw+4VCRhiQyRvzB8j6Th4b\n-----END CERTIFICATE-----')
                if 'RAILWAY_SECURITY_JWT_PUBLIC_KEY' in d1:
                    d1.update(RAILWAY_SECURITY_JWT_PUBLIC_KEY=r'-----BEGIN CERTIFICATE-----\nMIIEjjCCA3agAwIBAgIQa6mHezhUHjZSoQkujiBSvzANBgkqhkiG9w0BAQsFADCB\ngzELMAkGA1UEBhMCTkwxEDAOBgNVBAgMB1V0cmVjaHQxEDAOBgNVBAcMB1V0cmVj\naHQxIzAhBgNVBAoMGkNvb3BlcmF0aWV2ZSBSYWJvYmFuayBVLkEuMSswKQYDVQQD\nDCJSYWJvYmFuayBPcGVuREFUQSBOb25Qcm9kdWN0aW9uIEcxMB4XDTIyMDQxMTEy\nNTkxN1oXDTIzMDUxMTEzNTkxN1owLjEsMCoGA1UEAwwjand0LXRyYW5zbWl0LWRl\ndi5wcm9qZWN0LXJhaWx3YXkubmwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\nAoIBAQCTbV2PKoqZ9z1oC3OIYzPCk0rLxwovg/AN29og2kbLrpdJD+5bfdQUVA2W\nl1+aGncnbZKjdC9ctn1CYNo9oIUC3qKyPo9ZUuaYYf7L3lOYZ43D30hZew+gW/4m\nUvTVgqHlWjHrxMDiOkoTU5eCeuTDG04jiAxumPFA2qdEkMKWgjqaTXxNt4Xi8OL/\nsEeu5kF6pIZWFgnztz6GGE3DhefY/afNrIhYrEzl+p2wzVph9KlsOqSoSDsquQCi\njT4I5sHW0SPzNe1NHJz0Wt7DBBORbbbWlExVKeZcgFMXGAFURmVmlh0GE22IBeMD\nwva7jYCIxlIjLs+fTScjKbeT4Pu1AgMBAAGjggFQMIIBTDBUBgNVHREETTBLgiRq\nd3QtdHJhbnNtaXQtdGVzdC5wcm9qZWN0LXJhaWx3YXkubmyCI2p3dC10cmFuc21p\ndC1kZXYucHJvamVjdC1yYWlsd2F5Lm5sMAkGA1UdEwQCMAAwHwYDVR0jBBgwFoAU\nmWH50DH+7O+w56N0pJedA9wn7oswHQYDVR0OBBYEFB99+FBqoUZJ3SB6xAjiYWRQ\nSKWcMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUH\nAwIwegYDVR0fBHMwcTBvoG2ga4ZpaHR0cDovL3JhaWx3YXktbm9ucHJvZC1jcmwt\nYnVja2V0LnMzLmV1LXdlc3QtMS5hbWF6b25hd3MuY29tL2NybC8xOTQ5NmNlOS01\nNzZjLTRiNjItODY3MS1jNGYzODZiNjk1YzIuY3JsMA0GCSqGSIb3DQEBCwUAA4IB\nAQBKb8Il5VrCXfU4xrRZBjcjylrlgCKqMAvhKAp+r1adYV1Sbqf0tw5ZhLwHJMUB\nAeDFcPmW64z1gufOgdEtD5GOuHyfIDephl0V0JUn+PCUHwZ6ohRn+xSIxLeYcdFx\nxptaC8ut9yrRx77E/K3rY4t6fLupXhFb0fYDvtsBG5ruvmSRMueN3O7G2f944lA1\nOUiB8ZGZ3m2oAmxjfMT4KC/oVC0DUfaoPOtO64+8eRjQMih8+6TErpl01zstfRV4\nTkFK3r55hAnG2go7zwf9KbyttugzVJa9Y7npln2AkRiH4nXNVXnn/r3BItAk2beN\n/WIw+4VCRhiQyRvzB8j6Th4b\n-----END CERTIFICATE-----')
                # logger.info(json.dumps(d1).replace(r"\\n",r"\n"))
                    if len(d1.keys()) == key_length:
                        # CALLING AWS SM TO UPDATE SECRET
                        # client.put_secret_value(SecretId=sec_item[1],SecretString= json.dumps(d1).replace(r"\\n",r"\n"))
                        logger.info(f"\n\n\n\n {sec_item[0]}")
                        logger.info(json.dumps(d1))
                        sleep(2)
                        file_contaning_jwt_cert.append(sec_item[0])
                else:
                    file_not_cotaining_cert.append(sec_item[0] )
                
        
        except Exception as e:
            
            logger.error(f"EXCEPTION OCCURRED AND COULD NOT UPDATE THE CERT: {sec_item[0]} \n ")
            
            file_not_cotaining_cert.append(sec_item[0])
    
    
    # END FOR LOOP
    
    
        # '''
    # UPLOADING FILE TO S3 BUCKET : cert-inventory-lambda
    # '''
        
    s3_client = boto3.client('s3')
    bucket = "cert-inventory-lambda"
    file1 = f"/tmp/secrets_updated.json"
    file2 = f"/tmp/secrets_not_updated.json"
    
    with open(file1, "w+") as f1:
        f1.write(json.dumps({"updated_secrets": file_contaning_jwt_cert}))
    f1.close()
    
    
    s3_client.upload_file(file1, bucket, "secrets_updated.json")
    logger.info("uploaded the updated secrets file")
    
    
    with open(file2, "w+") as f2:
        f2.write(json.dumps({"not_updated_secrets": file_not_cotaining_cert}))
    f2.close()
    
    s3_client.upload_file(file2, bucket, "secrets_not_updated.json")
    
    logger.info("uploaded the not updated secrets file")
    logging.shutdown()
    sleep(2)
    s3_client.upload_file("/tmp/myloggingfile.log", bucket, "jwtcert.log")