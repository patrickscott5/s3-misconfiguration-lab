import boto3
import json
from botocore.exceptions import ClientError

def check_bucket_public_access(s3_client, bucket_name):
    try:
        response = s3_client.get_public_access_block(Bucket=bucket_name)
        config = response['PublicAccessBlockConfiguration']
        block_public_access = all([
            config['BlockPublicAcls'],
            config['IgnorePublicAcls'],
            config['BlockPublicPolicy'],
            config['RestrictPublicBuckets']
        ])
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
            block_public_access = False
        else:
            raise

    has_public_policy = False
    try:
        policy = s3_client.get_bucket_policy(Bucket=bucket_name)
        policy_json = json.loads(policy['Policy'])
        for statement in policy_json['Statement']:
            if statement.get('Effect') == 'Allow':
                principal = statement.get('Principal')
                if principal == '*' or (isinstance(principal, dict) and '*' in principal.get('AWS', [])):
                    has_public_policy = True
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
            has_public_policy = False
        else:
            raise

    return {
        'bucket': bucket_name,
        'block_public_access_enabled': block_public_access,
        'has_public_policy': has_public_policy,
        'is_vulnerable': not block_public_access and has_public_policy
    }

def main():
    s3 = boto3.client('s3')
    response = s3.list_buckets()
    buckets = response['Buckets']

    print(f"\n{'='*50}")
    print(f"S3 PUBLIC ACCESS AUDIT")
    print(f"Scanning {len(buckets)} bucket(s)...")
    print(f"{'='*50}\n")

    vulnerable_buckets = []

    for bucket in buckets:
        bucket_name = bucket['Name']
        result = check_bucket_public_access(s3, bucket_name)

        status = "VULNERABLE" if result['is_vulnerable'] else "SECURE"
        print(f"Bucket: {bucket_name}")
        print(f"Status: {status}")
        print(f"  Block Public Access: {'Enabled' if result['block_public_access_enabled'] else 'DISABLED'}")
        print(f"  Public Bucket Policy: {'YES - EXPOSED' if result['has_public_policy'] else 'No'}")
        print()

        if result['is_vulnerable']:
            vulnerable_buckets.append(bucket_name)

    print(f"{'='*50}")
    print(f"SUMMARY")
    print(f"{'='*50}")
    print(f"Total buckets scanned: {len(buckets)}")
    print(f"Vulnerable buckets found: {len(vulnerable_buckets)}")

    if vulnerable_buckets:
        print(f"\nACTION REQUIRED - Publicly exposed buckets:")
        for b in vulnerable_buckets:
            print(f"  - {b}")
    else:
        print("\nNo publicly exposed buckets found.")

if __name__ == "__main__":
    main()
