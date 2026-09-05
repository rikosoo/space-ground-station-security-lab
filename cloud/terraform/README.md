# Cloud instantiation

Terraform for the AWS deployment of the architecture measured in the paper.
The stack is the deployed twin of the offline testbed: the detection logic in
`cloud/lambda/detector` imports the same rule pack (`src/spacelab/siem`) that the
experiments run, shipped as a Lambda layer.

## Layout

| File | Contents |
|---|---|
| `versions.tf` | Provider pinning and default tags |
| `variables.tf` | Inputs; `alert_email` is the only one usually set |
| `main.tf` | Kinesis stream, KMS key, telemetry archive, CloudTrail |
| `detection.tf` | Detector and responder Lambdas, EventBridge, Security Hub, GuardDuty, alarms |
| `iam.tf` | Least-privilege roles and the quarantine policy |
| `outputs.tf` | Names the ground-station agent needs |

## Deploy

```bash
cd cloud
make layer                     # packages src/spacelab into a Lambda layer
cd terraform
terraform init
terraform plan  -var="alert_email=soc@example.org"
terraform apply -var="alert_email=soc@example.org"
```

`terraform destroy` removes everything except the audit bucket, which is
retained deliberately: destroying the evidence trail with the stack would
defeat the purpose of having one.

## Cost

`python research/experiments/run_experiment.py cost` prints the modelled monthly
bill for this stack at one, ten and one hundred spacecraft. At lab scale the
dominant line is the minimum billable capacity of the search tier, not event
volume.
