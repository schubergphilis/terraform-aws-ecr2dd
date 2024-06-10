import boto3
import json
import requests
import urllib

def get_highest_severity(severity_counts):
    if severity_counts['CRITICAL'] > 0:
        return 'CRITICAL'
    if severity_counts['HIGH'] > 0:
        return 'HIGH'
    if severity_counts['MEDIUM'] > 0:
        return 'MEDIUM'
    return 'LOW'

def get_dd_secret(boto3, secretarn):
    service_client = boto3.client('secretsmanager')
    secret = service_client.get_secret_value(SecretId=secretarn)
    plaintext = secret['SecretString']
    secret_dict = json.loads(plaintext)

    # Run validations against the secret
    required_fields = ['apikey', 'url']
    for field in required_fields:
        if field not in secret_dict:
            raise KeyError("%s key is missing from secret JSON" % field)

    return secret_dict


def get_repo_name(repo_arn):
    return repo_arn.split("repository/")[1]


def get_repo_config(repo_arn):
  config = json.loads(os.environ['REPO_CONFIG'])
  # get the config that matches the repo_arn
  for repo in config:
      if repo['ecr_base_name'] in get_repo_name(repo_arn):
        return config[repo]


def get_repo_tag(repo_config):
    if repo_config['ecr_repo_tag']:
        return repo_config['ecr_repo_tag']
    else:
        return repo['ecr_base_name']


def lambda_handler(event, context):
    print("Received event: " + json.dumps(event, indent=2))
    print("Raw event: ")
    print(event)
    print("End raw event")

    repo_config = get_repo_config(event['detail']['repository-name'])

    dd_secret_arn = repo_config['dd_secret_arn']
    dd_secret_data = get_dd_secret(boto3, dd_secret_arn)

    datadog_api_key = dd_secret_data['apikey']
    datadog_url = dd_secret_data['url']

    headers = {
        'Content-Type': 'application/json',
        'DD-API-KEY': datadog_api_key
    }
    
    region = event['region']
    url_encoded_repo_sha = urllib.parse.quote_plus(event['detail']['repository-name'] + "/" + event['detail']['image-digest'])
    scan_url="https://" + region + ".console.aws.amazon.com/inspector/v2/home?region=" + region + "#/findings/container-image/" + url_encoded_repo_sha
    
    payload_text = '''
    %%% \n
    Vulnerability found in: `{repo_arn}/{image_digest}`.
    [Scan results]({scan_url})
    
    ```
    Repository:     {repo_arn}
    Image SHA:      {image_digest}
    Image tags:     [{image_tags_list}]
    
    Criticals:      {findings_crit}
    Highs:          {findings_high}
    Mediums:        {findings_med}
    ```
    \n %%%
    '''.format(
        findings_crit=event['detail']['finding-severity-counts']['CRITICAL'],
        findings_high=event['detail']['finding-severity-counts']['HIGH'],
        findings_med=event['detail']['finding-severity-counts']['MEDIUM'],
        image_digest=event['detail']['image-digest'],
        image_tags_list=", ".join(event['detail']['image-tags']),
        repo_arn=event['detail']['repository-name'],
        scan_url=scan_url
    )
    
    payload = {
        "title": "ECR Scan finding in " + event['detail']['repository-name'].split("repository/")[1],
        "text": payload_text,
        "aggregation_key": event['detail']['repository-name'] + "/" + event['detail']['image-digest'],
        "source_type_name": "amazon inspector",
        "tags": [
            "env:sandbox",
            "image_sha:" + event['detail']['image-digest'],
            "repo_arn:" + event['detail']['repository-name'],
            "repo_base:" + get_repo_tag(repo_config),
            "severity:" + get_highest_severity(event['detail']['finding-severity-counts'])
        ]
    }

    print(json.dumps(payload))
    
    response = requests.post(datadog_url, headers=headers, data=json.dumps(payload))
    
    if response.status_code != 200:
        print("Error posting to Datadog: " + str(response.status_code))
        print(response.content)
    
        return {
            'statusCode': 500,
            'body': json.dumps('Error forwarding ECR scanning event to Datadog')
        }
    else:
        return {
            'statusCode': 200,
            'body': json.dumps('ECR scanning event forwarded to Datadog successfully')
        }


