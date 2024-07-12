## github-aws-scan - v1.0
##
## Proudly written by our new AI overlords, with my oversight and guidance.
## save file locally with --save
## Excludes common image files and performs string operation on exe and dll (requires "strings" binary in the path)

import argparse
import requests
import re
import subprocess
import os
import logging

# Constants
GITHUB_TOKEN = 'GITHUB_TOKEN'
REPO_OWNER = 'GITHUB_OWNER'
GITHUB_API_URL = 'https://api.github.com'
DEFAULT_LOCAL_SAVE_PATH = 'downloaded_files'  # Local directory to save downloaded files
DEFAULT_SENSITIVE_INFO_LOG = 'WOOHOO.txt'    # File to log URLs of files with sensitive information
DEFAULT_PROGRESS_LOG = 'scan_progress.log'   # File to log scanning progress

# Headers for GitHub API requests
headers = {
    'Authorization': f'token {GITHUB_TOKEN}',
    'Accept': 'application/vnd.github.v3+json'
}

# Patterns to search for sensitive AWS information
aws_patterns = [
    re.compile(r'AKIA[0-9A-Z]{16}'),  # AWS Access Key ID
    re.compile(r'(?i)aws_secret_access_key\s*=\s*["\']?([A-Za-z0-9/+=]{40})["\']?'),  # AWS Secret Access Key
    re.compile(r'(?i)aws_session_token\s*=\s*["\']?([A-Za-z0-9/+=]+)["\']?'),  # AWS Session Token
    re.compile(r'(?i)aws_security_token\s*=\s*["\']?([A-Za-z0-9/+=]+)["\']?'),  # AWS Security Token
    re.compile(r'arn:aws:[a-zA-Z0-9_/-]+:[a-zA-Z0-9_/-]+:[0-9]{12}:[a-zA-Z0-9_/-]+'),  # AWS ARN
    re.compile(r's3://[a-zA-Z0-9.-]+/[a-zA-Z0-9./-]*'),  # S3 bucket URLs
    re.compile(r'arn:aws:iam::[0-9]{12}:role/[a-zA-Z0-9_/-]+'),  # IAM Role ARN
    re.compile(r'arn:aws:iam::[0-9]{12}:policy/[a-zA-Z0-9_/-]+'),  # IAM Policy ARN
    re.compile(r'aws_access_key_id\s*=\s*["\']?([A-Z0-9]{20})["\']?\s*aws_secret_access_key\s*=\s*["\']?([A-Za-z0-9/+=]{40})["\']?'),  # AWS Access Key and Secret
    re.compile(r'(?i)distributions/[a-zA-Z0-9]+'),  # CloudFront Distribution ID
    re.compile(r'arn:aws:lambda:[a-zA-Z0-9_-]+:[0-9]{12}:function:[a-zA-Z0-9-_]+'),  # Lambda Function ARN
    re.compile(r'arn:aws:kms:[a-zA-Z0-9_-]+:[0-9]{12}:key/[a-zA-Z0-9-]+'),  # KMS Key ARN
    re.compile(r'arn:aws:secretsmanager:[a-zA-Z0-9_-]+:[0-9]{12}:secret:[a-zA-Z0-9-_:/]+'),  # Secrets Manager ARN
    re.compile(r'rds:[a-zA-Z0-9-]+'),  # RDS Instance Identifier
    re.compile(r'i-[a-f0-9]{17}'),  # EC2 Instance ID
    re.compile(r'[0-9]{12}.dkr.ecr.[a-z0-9-]+.amazonaws.com/[a-zA-Z0-9-_./]+'),  # ECR Repository URI
    re.compile(r'arn:aws:elasticbeanstalk:[a-zA-Z0-9_-]+:[0-9]{12}:environment/[a-zA-Z0-9-]+/[a-zA-Z0-9-]+'),  # Elastic Beanstalk Environment ARN
]

# Common image file extensions to exclude
image_extensions = ('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.svg', '.webp', '.tiff')

# Common binary file extensions to include for strings extraction
binary_extensions = ('.exe', '.dll')

def get_repo_list(owner):
    url = f'{GITHUB_API_URL}/users/{owner}/repos'
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()

def get_repo_files(repo_url, path=''):
    url = f'{repo_url}/contents/{path}'
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()

def search_file_content(file_url):
    response = requests.get(file_url, headers=headers)
    response.raise_for_status()
    return response.content

def extract_strings_from_binary(content):
    process = subprocess.Popen(['strings'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate(input=content)
    if process.returncode != 0:
        raise Exception(f"strings command failed: {stderr.decode()}")
    return stdout.decode()

def search_for_sensitive_info(content, file_url):
    sensitive_info = []
    for pattern in aws_patterns:
        matches = pattern.findall(content)
        if matches:
            for match in matches:
                sensitive_info.append((file_url, match))
    return sensitive_info

def save_file_locally(repo_name, file_path, content):
    repo_path = os.path.join(DEFAULT_LOCAL_SAVE_PATH, repo_name)
    local_path = os.path.join(repo_path, file_path)
    os.makedirs(os.path.dirname(local_path), exist_ok=True)
    with open(local_path, 'wb') as f:
        f.write(content)

def log_sensitive_info(file_url):
    with open(DEFAULT_SENSITIVE_INFO_LOG, 'a') as log_file:
        log_file.write(file_url + '\n')

def setup_logging(progress_log_file):
    logging.basicConfig(filename=progress_log_file, level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s')

def scan_repository(repo, save_files):
    repo_name = repo['name']
    repo_url = repo['url']
    logging.info(f"Scanning repository: {repo_name}")
    print(f"Scanning repository: {repo_name}")
    
    try:
        files = get_repo_files(repo_url)
        sensitive_info = []
        file_count = 0
        
        for file in files:
            if file['type'] == 'file':
                file_name = file['name'].lower()
                file_url = file['download_url']
                if file_name.endswith(image_extensions):
                    logging.info(f"Skipped image file: {file['path']}")
                    print(f"Skipped image file: {file['path']}")
                    continue
                
                file_content = search_file_content(file_url)
                
                if save_files:
                    save_file_locally(repo_name, file['path'], file_content)  # Save file locally
                
                if file_name.endswith(binary_extensions):
                    strings_content = extract_strings_from_binary(file_content)
                    sensitive_info.extend(search_for_sensitive_info(strings_content, file_url))
                else:
                    text_content = file_content.decode('utf-8', errors='ignore')
                    sensitive_info.extend(search_for_sensitive_info(text_content, file_url))
                
                file_count += 1
                logging.info(f"Processed file {file_count}: {file['path']}")
                print(f"Processed file {file_count}: {file['path']}")
            elif file['type'] == 'dir':
                dir_files = get_repo_files(repo_url, file['path'])
                for dir_file in dir_files:
                    if dir_file['type'] == 'file':
                        file_name = dir_file['name'].lower()
                        file_url = dir_file['download_url']
                        if file_name.endswith(image_extensions):
                            logging.info(f"Skipped image file: {dir_file['path']}")
                            print(f"Skipped image file: {dir_file['path']}")
                            continue
                        
                        file_content = search_file_content(file_url)
                        
                        if save_files:
                            save_file_locally(repo_name, dir_file['path'], file_content)  # Save file locally

                        if file_name.endswith(binary_extensions):
                            strings_content = extract_strings_from_binary(file_content)
                            sensitive_info.extend(search_for_sensitive_info(strings_content, file_url))
                        else:
                            text_content = file_content.decode('utf-8', errors='ignore')
                            sensitive_info.extend(search_for_sensitive_info(text_content, file_url))
                        
                        file_count += 1
                        logging.info(f"Processed file {file_count}: {dir_file['path']}")
                        print(f"Processed file {file_count}: {dir_file['path']}")
        
        if sensitive_info:
            logging.info(f"Sensitive AWS Information Found in {repo_name}:")
            print(f"Sensitive AWS Information Found in {repo_name}:")
            for info in sensitive_info:
                logging.info(f"File: {info[0]}, Sensitive Data: {info[1]}")
                print(f"File: {info[0]}, Sensitive Data: {info[1]}")
                log_sensitive_info(info[0])  # Log file URL to sensitive_info_log
        else:
            logging.info(f"No sensitive AWS information found in {repo_name}.")
            print(f"No sensitive AWS information found in {repo_name}.")
        
        logging.info(f"Finished scanning repository: {repo_name} (Total files processed: {file_count})")
        print(f"Finished scanning repository: {repo_name} (Total files processed: {file_count})")

    except requests.exceptions.RequestException as e:
        logging.error(f"Error scanning repository {repo_name}: {e}")
        print(f"Error scanning repository {repo_name}: {e}")

def main():
    parser = argparse.ArgumentParser(description="Scan GitHub repositories for sensitive AWS information.")
    parser.add_argument('--save', action='store_true', help="Save files locally.")
    parser.add_argument('--log', type=str, default=DEFAULT_PROGRESS_LOG, help="Log file to capture scanning progress.")
    
    args = parser.parse_args()

    save_files = args.save
    progress_log_file = args.log

    # Clear the sensitive info log file at the start
    open(DEFAULT_SENSITIVE_INFO_LOG, 'w').close()

    # Set up logging
    setup_logging(progress_log_file)

    try:
        repos = get_repo_list(REPO_OWNER)
        total_repos = len(repos)
        logging.info(f"Total repositories to scan: {total_repos}")
        print(f"Total repositories to scan: {total_repos}")

        for i, repo in enumerate(repos, 1):
            logging.info(f"\nScanning repository {i}/{total_repos}")
            print(f"\nScanning repository {i}/{total_repos}")
            scan_repository(repo, save_files)

    except requests.exceptions.RequestException as e:
        logging.error(f"Error: {e}")
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
