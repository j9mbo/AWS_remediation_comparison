# AWS Remediation Comparison

This repository contains code, infrastructure templates, and experiment data for comparing automated and manual remediation of AWS security misconfigurations.

## Project Structure

- **lambda_function.py**: EventBridge-triggered Lambda for automated remediation of S3 bucket policies and EC2 Security Group ingress rules.
- **lambda_function_2.py**: AWS Config-triggered Lambda for compliance evaluation of S3 buckets and Security Groups.
- **infra_cloud_form.yml**: CloudFormation template to deploy the experiment infrastructure (VPC, S3 bucket, Security Group, IAM Role).
- **attack-policy.json**: Example public access policy used to simulate S3 bucket misconfiguration.
- **manual_test_results.csv**: Results of manual remediation experiments.
- **new_plot.py**: Python script for visualizing experiment results.
- **.env**: AWS credentials (excluded from version control).
- **.gitignore**: Ensures sensitive and environment-specific files are not tracked.

## Experiment Scenarios

### 1. S3 Bucket Public Policy

Simulates a public access misconfiguration.  
Automated remediation via Lambda deletes the public policy and re-enables Block Public Access.

**Attack Step 1:**  
Run the following commands to turn off the safety switch and apply a public policy (replace with your bucket name if needed):

```
aws s3api put-public-access-block --bucket remediation-experiment-test-bucket-913524935822-eu-north-1 --public-access-block-configuration "BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false"

aws s3api put-bucket-policy --bucket remediation-experiment-test-bucket-913524935822-eu-north-1 --policy file://attack-policy.json
```

### 2. Security Group Unrestricted SSH

Simulates an SSH port open to the world.  
Automated remediation via Lambda revokes the unrestricted ingress rule.

**Attack Step 2:**  
Run the following command to open SSH to the world:

```
aws ec2 authorize-security-group-ingress --group-id sg-0f5b30b6b25875623 --protocol tcp --port 22 --cidr 0.0.0.0/0
```

## Lambda Permission Example

To allow AWS Config to invoke your remediation Lambda, use:

```
aws lambda add-permission \
--function-name SecurityRemediationFunction \
--statement-id Config-Invoke-Permission-S3-Rule \
--action "lambda:InvokeFunction" \
--principal "config.amazonaws.com" \
--source-arn "arn:aws:controlcatalog:::control/8sw3pbid15t9cbww8d2w2qwgf"
```

## How to Deploy

1. **Deploy Infrastructure**
   - Use `infra_cloud_form.yml` with AWS CloudFormation.

2. **Configure Lambda Functions**
   - Deploy `lambda_function.py` and `lambda_function_2.py` as AWS Lambda functions.
   - Assign the IAM role created by the CloudFormation stack.

3. **Run Experiments**
   - Trigger misconfigurations using the commands above.
   - Observe automated remediation and record manual remediation times.

## Data Analysis

- Use `new_plot.py` to generate comparative plots of remediation times.

## Security Notice

- **Do not commit real AWS credentials.** The `.env` file is ignored by `.gitignore`.

## License

This project is for academic/research purposes.
