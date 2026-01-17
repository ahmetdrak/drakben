# modules/cloud_enum.py
import subprocess

def aws_enum(profile="default"):
    cmd = f"aws s3 ls --profile {profile}"
    return subprocess.getoutput(cmd)

def azure_enum():
    cmd = "az storage account list"
    return subprocess.getoutput(cmd)

def gcp_enum():
    cmd = "gcloud projects list"
    return subprocess.getoutput(cmd)
