import boto3
import json
import logging
import traceback

# --- Standard Setup ---
logger = logging.getLogger()
logger.setLevel(logging.INFO)
s3_client = boto3.client('s3')
ec2_client = boto3.client('ec2')

# --- Main Handler ---
def lambda_handler(event, context):
    logger.info("--- Lambda Invocation Start ---")
    logger.info("Event Received: " + json.dumps(event))
    
    event_source = event.get('source')
    event_name = event.get('detail', {}).get('eventName')
    
    logger.info(f"ROUTING: Detected event source: [{event_source}] and event name: [{event_name}]")

    # --- Routing Logic ---
    if event_source == 'aws.s3' and event_name == 'PutBucketPolicy':
        logger.info("ROUTE: Matched S3 PutBucketPolicy event. Starting S3 remediation.")
        result = remediate_s3_policy(event)
        
    elif event_source == 'aws.ec2' and event_name == 'AuthorizeSecurityGroupIngress':
        logger.info("ROUTE: Matched EC2 AuthorizeSecurityGroupIngress event. Starting Security Group remediation.")
        result = remediate_security_group(event)
        
    else:
        logger.warning("ROUTE: Event did not match any remediation rule. No action taken.")
        result = {'status': 'ignored', 'reason': 'Unsupported event'}
    
    logger.info(f"--- Lambda Invocation End. Final Status: {result.get('status')} ---")
    return result

# --- Remediation Logic for S3 ---
def remediate_s3_policy(event):
    try:
        bucket_name = event['detail']['requestParameters']['bucketName']
        policy_dict = event['detail']['requestParameters']['bucketPolicy']
        policy_text = json.dumps(policy_dict)
        
        logger.info(f"S3_CHECK: Analyzing policy for bucket: {bucket_name}")
        
        is_public = '"Principal":"*"' in policy_text.replace(" ", "") or \
                    '"Principal":{"AWS":"*"}' in policy_text.replace(" ", "")

        if is_public:
            logger.info(f"S3_CHECK_RESULT: Policy for {bucket_name} is PUBLIC. Proceeding with remediation.")

            # Step 1: Delete Policy
            logger.info(f"S3_ACTION: Attempting to delete bucket policy from {bucket_name}...")
            s3_client.delete_bucket_policy(Bucket=bucket_name)
            logger.info(f"S3_SUCCESS: Successfully deleted public policy from bucket: {bucket_name}")

            # Step 2: Block Public Access
            logger.info(f"S3_ACTION: Attempting to re-enable Block Public Access on {bucket_name}...")
            s3_client.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True, 'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True, 'RestrictPublicBuckets': True
                }
            )
            logger.info(f"S3_SUCCESS: Successfully re-enabled Block Public Access on bucket: {bucket_name}")
            return {'status': 'success', 'bucket': bucket_name}
        else:
            logger.info(f"S3_CHECK_RESULT: Policy for {bucket_name} was not public. Ignoring.")
            return {'status': 'ignored', 'reason': 'Policy was not public'}

    except Exception as e:
        logger.error(f"S3_ERROR: An exception occurred during S3 remediation: {str(e)}")
        traceback.print_exc()
        return {'status': 'error', 'reason': str(e)}

# --- Remediation Logic for Security Groups ---
def remediate_security_group(event):
    try:
        sg_id = event['detail']['requestParameters']['groupId']
        logger.info(f"SG_CHECK: Analyzing ingress rules for Security Group: {sg_id}")
        
        for item in event['detail']['requestParameters']['ipPermissions'].get('items', []):
            is_ssh = item.get('fromPort') == 22 and item.get('toPort') == 22
            
            if is_ssh:
                for ip_range in item.get('ipRanges', {}).get('items', []):
                    if ip_range.get('cidrIp') == '0.0.0.0/0':
                        logger.info(f"SG_CHECK_RESULT: Unrestricted SSH rule found in {sg_id}. Proceeding with remediation.")
                        
                        rule_to_revoke = {'IpProtocol': item.get('ipProtocol'),'FromPort': 22,'ToPort': 22,'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
                        
                        logger.info(f"SG_ACTION: Attempting to revoke ingress rule from {sg_id}...")
                        ec2_client.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=[rule_to_revoke])
                        logger.info(f"SG_SUCCESS: Successfully revoked unrestricted SSH rule from Security Group: {sg_id}")
                        return {'status': 'success', 'security_group': sg_id}

        logger.info(f"SG_CHECK_RESULT: No unrestricted SSH rule found in the triggering event for {sg_id}. Ignoring.")
        return {'status': 'ignored', 'reason': 'Not an unrestricted SSH rule'}
        
    except Exception as e:
        logger.error(f"SG_ERROR: An exception occurred during Security Group remediation: {str(e)}")
        traceback.print_exc()
        return {'status': 'error', 'reason': str(e)}