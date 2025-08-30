import boto3
import json
import logging

# --- Standard Setup ---
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients outside the handler for best practice
s3_client = boto3.client('s3')
ec2_client = boto3.client('ec2')
config_client = boto3.client('config')

def lambda_handler(event, context):
    """
    Main handler. This function is invoked by AWS Config. It parses the event
    and routes to the correct evaluation logic based on a parameter we set in the rule.
    """
    logger.info("Received event: " + json.dumps(event))
    
    # Extract the necessary details from the incoming event
    invoking_event = json.loads(event['invokingEvent'])
    
    # The ruleParameters will tell us which scenario to check
    try:
        rule_parameters = json.loads(event['ruleParameters'])
        scenario_to_check = rule_parameters.get('scenario')
    except (json.JSONDecodeError, KeyError):
        logger.error("Could not parse ruleParameters or find 'scenario' key.")
        # Report failure if parameters are missing
        report_evaluation(invoking_event, event['resultToken'], 'NOT_APPLICABLE', annotation="Missing 'scenario' parameter in rule.")
        return

    # --- Routing Logic ---
    if scenario_to_check == 'S3_PUBLIC_POLICY':
        evaluate_s3_compliance(invoking_event, event['resultToken'])
    elif scenario_to_check == 'SG_UNRESTRICTED_SSH':
        evaluate_sg_compliance(invoking_event, event['resultToken'])
    else:
        logger.warning(f"Unknown scenario: {scenario_to_check}. No action taken.")
        report_evaluation(invoking_event, event['resultToken'], 'NOT_APPLICABLE', annotation=f"Unknown scenario '{scenario_to_check}'.")

def evaluate_s3_compliance(invoking_event, result_token):
    """
    Evaluates an S3 bucket for public policies or disabled Block Public Access settings.
    """
    config_item = invoking_event['configurationItem']
    bucket_name = config_item['resourceName']
    compliance_type = 'COMPLIANT'  # Assume compliant by default
    annotation = "S3 bucket is configured securely."

    try:
        # Check 1: Is Block Public Access disabled?
        bpa_config = s3_client.get_public_access_block(Bucket=bucket_name)['PublicAccessBlockConfiguration']
        if not all(bpa_config.values()):
            compliance_type = 'NON_COMPLIANT'
            annotation = "Block Public Access is not fully enabled."
        
        # Check 2: Does a public policy exist? (Only check if still compliant)
        if compliance_type == 'COMPLIANT':
            try:
                policy_text = s3_client.get_bucket_policy(Bucket=bucket_name)['Policy']
                policy = json.loads(policy_text)
                for statement in policy.get('Statement', []):
                    # Check for "Principal": "*" which indicates a public policy
                    principal = statement.get('Principal')
                    if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                        if statement.get('Effect') == 'Allow':
                            compliance_type = 'NON_COMPLIANT'
                            annotation = "Bucket has a public policy."
                            break
            except s3_client.exceptions.NoSuchBucketPolicy:
                # This is good. No policy means it's not public.
                pass
            
    except Exception as e:
        logger.error(f"Error evaluating S3 bucket {bucket_name}: {e}")
        # If we can't check, it's safer to mark it as non-compliant
        compliance_type = 'NON_COMPLIANT'
        annotation = f"An error occurred during evaluation: {e}"

    report_evaluation(invoking_event, result_token, compliance_type, annotation=annotation)


def evaluate_sg_compliance(invoking_event, result_token):
    """
    Evaluates an EC2 Security Group for unrestricted SSH ingress rules.
    """
    config_item = invoking_event['configurationItem']
    sg_id = config_item['resourceId']
    compliance_type = 'COMPLIANT' # Assume compliant by default
    annotation = "Security Group is configured securely."
    
    try:
        response = ec2_client.describe_security_groups(GroupIds=[sg_id])
        for rule in response['SecurityGroups'][0].get('IpPermissions', []):
            is_ssh_port = rule.get('FromPort') == 22 and rule.get('ToPort') == 22
            if is_ssh_port:
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        compliance_type = 'NON_COMPLIANT'
                        annotation = "Security Group has SSH (port 22) open to the world (0.0.0.0/0)."
                        break
            if compliance_type == 'NON_COMPLIANT':
                break
    except Exception as e:
        logger.error(f"Error evaluating Security Group {sg_id}: {e}")
        compliance_type = 'NON_COMPLIANT'
        annotation = f"An error occurred during evaluation: {e}"
        
    report_evaluation(invoking_event, result_token, compliance_type, annotation=annotation)

def report_evaluation(invoking_event, result_token, compliance_type, annotation=""):
    """
    Helper function to send the evaluation result back to AWS Config.
    """
    config_item = invoking_event['configurationItem']
    evaluation = {
        'ComplianceResourceType': config_item['resourceType'],
        'ComplianceResourceId': config_item['resourceId'], # For SG
        'ComplianceType': compliance_type,
        'Annotation': annotation,
        'OrderingTimestamp': config_item['configurationItemCaptureTime']
    }
    # S3 buckets use resourceName, not resourceId in this context
    if config_item['resourceType'] == 'AWS::S3::Bucket':
        evaluation['ComplianceResourceId'] = config_item['resourceName']
        
    config_client.put_evaluations(
        Evaluations=[evaluation],
        ResultToken=result_token
    )