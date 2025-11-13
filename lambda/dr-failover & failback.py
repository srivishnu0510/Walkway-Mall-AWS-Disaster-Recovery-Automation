# dr-controller.py
import os
import json
import logging
import boto3
from botocore.exceptions import ClientError

# --- Configuration from environment variables ---
PRIMARY_INSTANCE_ID = os.environ['PRIMARY_INSTANCE_ID']
PRIMARY_EIP = os.environ['PRIMARY_EIP']
DR_INSTANCE_ID = os.environ['DR_INSTANCE_ID']
DR_REGION = os.environ.get('DR_REGION', 'us-west-2')
HOSTED_ZONE_ID = os.environ['HOSTED_ZONE_ID']
DNS_RECORD_NAME = os.environ['DNS_RECORD_NAME']
SNS_TOPIC_ARN = os.environ['SNS_TOPIC_ARN']
ROUTE53_TTL = int(os.environ.get('ROUTE53_TTL', '60'))

LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()
logging.basicConfig(level=getattr(logging, LOG_LEVEL))
log = logging.getLogger('dr-controller')

# --- Boto3 clients ---
ec2_primary = boto3.client('ec2')
ec2_dr = boto3.client('ec2', region_name=DR_REGION)
route53 = boto3.client('route53')
sns = boto3.client('sns')

# --- Helpers ---
def publish_sns(subject, message):
    try:
        sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject, Message=message)
        log.info("SNS published: %s", subject)
    except ClientError as e:
        log.exception("Failed to publish SNS: %s", e)

def get_primary_status():
    """
    Returns tuple (is_running_bool, instance_state_str, instance_status_ok_bool, system_status_ok_bool)
    """
    try:
        resp = ec2_primary.describe_instance_status(InstanceIds=[PRIMARY_INSTANCE_ID], IncludeAllInstances=True)
    except ClientError as e:
        log.exception("Error describing primary instance status: %s", e)
        return False, "unknown", False, False

    statuses = resp.get('InstanceStatuses', [])
    if not statuses:
        # If no InstanceStatus returned, instance might be stopped/terminated or AWS hasn't reported yet
        log.debug("No instance status returned for primary")
        return False, "no-data", False, False

    st = statuses[0]
    state = st.get('InstanceState', {}).get('Name', 'unknown')
    inst_ok = st.get('InstanceStatus', {}).get('Status') == 'ok'
    sys_ok = st.get('SystemStatus', {}).get('Status') == 'ok'
    is_running = (state == 'running')
    log.debug("Primary state=%s, inst_ok=%s, sys_ok=%s", state, inst_ok, sys_ok)
    return is_running, state, inst_ok, sys_ok

def start_dr_instance():
    # Idempotent start
    try:
        # check DR instance state first
        desc = ec2_dr.describe_instances(InstanceIds=[DR_INSTANCE_ID])
        dr_state = desc['Reservations'][0]['Instances'][0]['State']['Name']
        log.info("DR current state: %s", dr_state)
        if dr_state == 'running':
            log.info("DR already running")
            # return public ip if exists
            pub = desc['Reservations'][0]['Instances'][0].get('PublicIpAddress')
            priv = desc['Reservations'][0]['Instances'][0].get('PrivateIpAddress')
            return pub or priv
        # start
        ec2_dr.start_instances(InstanceIds=[DR_INSTANCE_ID])
        waiter = ec2_dr.get_waiter('instance_running')
        log.info("Waiting for DR to enter running state...")
        waiter.wait(InstanceIds=[DR_INSTANCE_ID], WaiterConfig={'Delay': 10, 'MaxAttempts': 30})
        desc = ec2_dr.describe_instances(InstanceIds=[DR_INSTANCE_ID])
        inst = desc['Reservations'][0]['Instances'][0]
        dr_ip = inst.get('PublicIpAddress') or inst.get('PrivateIpAddress')
        log.info("DR instance running with IP: %s", dr_ip)
        return dr_ip
    except ClientError as e:
        log.exception("Failed to start DR instance: %s", e)
        raise

def stop_dr_instance():
    try:
        desc = ec2_dr.describe_instances(InstanceIds=[DR_INSTANCE_ID])
        dr_state = desc['Reservations'][0]['Instances'][0]['State']['Name']
        log.info("DR current state: %s", dr_state)
        if dr_state in ('stopping', 'stopped', 'shutting-down', 'terminated'):
            log.info("DR is not running; no action needed")
            return True
        ec2_dr.stop_instances(InstanceIds=[DR_INSTANCE_ID])
        waiter = ec2_dr.get_waiter('instance_stopped')
        log.info("Waiting for DR to stop...")
        waiter.wait(InstanceIds=[DR_INSTANCE_ID], WaiterConfig={'Delay': 10, 'MaxAttempts': 30})
        log.info("DR stopped")
        return True
    except ClientError as e:
        log.exception("Failed to stop DR instance: %s", e)
        raise

def update_route53(ip_address):
    """UPSERT the A record to the provided ip"""
    try:
        if not ip_address:
            raise ValueError("Empty IP for update_route53")
        change_batch = {
            'Comment': 'Automated DR change',
            'Changes': [{
                'Action': 'UPSERT',
                'ResourceRecordSet': {
                    'Name': DNS_RECORD_NAME,
                    'Type': 'A',
                    'TTL': ROUTE53_TTL,
                    'ResourceRecords': [{'Value': ip_address}]
                }
            }]
        }
        resp = route53.change_resource_record_sets(HostedZoneId=HOSTED_ZONE_ID, ChangeBatch=change_batch)
        log.info("Route53 updated to %s; ChangeInfo: %s", ip_address, resp.get('ChangeInfo', {}))
        return resp
    except ClientError as e:
        log.exception("Failed to update Route53: %s", e)
        raise

# --- Core logic ---
def perform_failover(reason=None):
    try:
        log.info("Executing failover. Reason: %s", reason)
        dr_ip = start_dr_instance()
        if not dr_ip:
            raise RuntimeError("DR started but IP could not be determined")
        update_route53(dr_ip)
        publish_sns("🚨 DR Failover Triggered", f"Primary instance {PRIMARY_INSTANCE_ID} failed. DR started at {dr_ip}. Reason: {reason}")
        return {"action": "failover", "dr_ip": dr_ip}
    except Exception as e:
        publish_sns("❌ DR Failover Failed", f"Failed to start DR or update DNS: {e}")
        log.exception("Failover exception")
        raise

def perform_failback(reason=None):
    try:
        log.info("Executing failback. Reason: %s", reason)
        # Stop DR first (idempotent)
        stop_dr_instance()
        # Restore DNS to primary EIP
        update_route53(PRIMARY_EIP)
        publish_sns("✅ DR Failback Completed", f"Primary instance {PRIMARY_INSTANCE_ID} healthy. Traffic returned to {PRIMARY_EIP}. Reason: {reason}")
        return {"action": "failback", "primary": PRIMARY_INSTANCE_ID}
    except Exception as e:
        publish_sns("❌ DR Failback Failed", f"Failed to stop DR or update DNS: {e}")
        log.exception("Failback exception")
        raise

def lambda_handler(event, context):
    """
    Main Lambda handler. Decides between failover and failback.

    Acceptable triggers:
    - CloudWatch Alarm state change (EventBridge): event['detail']['state']['value'] == 'ALARM' or 'OK'
    - Manual invocation (test) with {"action": "failover"} or {"action": "failback"}
    - Route53 health check SNS notification (if you configure it) - treat as failover when unhealthy
    - Generic invocation: will check Primary health and act (if unhealthy -> failover; if healthy and DR running -> failback)
    """
    log.info("Event received: %s", json.dumps(event)[:1000])

    # 1) If explicit action provided in event
    action = None
    # CloudWatch EventBridge Alarm pattern:
    # event['detail']['state']['value'] => "ALARM" or "OK"
    try:
        if isinstance(event, dict):
            # direct test payload
            if event.get('action') in ('failover', 'failback'):
                action = event.get('action')
            # CloudWatch Alarm via EventBridge
            elif event.get('detail', {}).get('state', {}).get('value') in ('ALARM', 'OK'):
                val = event['detail']['state']['value']
                log.info("CloudWatch/event state value: %s", val)
                if val == 'ALARM':
                    action = 'failover'
                elif val == 'OK':
                    action = 'failback'
            # CloudWatch Alarms when used as old-style may have a different format (SNS forwarded); try parse
            elif event.get('Records') and isinstance(event.get('Records'), list):
                # SNS -> Lambda subscriptions deliver SNS message in Records
                rec = event['Records'][0]
                if rec.get('EventSource') == 'aws:sns' or rec.get('Sns'):
                    msg = rec.get('Sns', {}).get('Message', '')
                    log.debug("SNS message: %s", msg)
                    # try to detect unhealthy keyword from Route53 or custom message
                    if 'UNHEALTHY' in msg.upper() or 'PRIMARY' in msg.upper() and 'UNHEALTHY' in msg.upper():
                        action = 'failover'
            # else, no explicit instruction
    except Exception:
        log.exception("Error parsing event for explicit action")

    # 2) If explicit action set, run
    if action == 'failover':
        return perform_failover(reason="explicit_trigger")
    if action == 'failback':
        return perform_failback(reason="explicit_trigger")

    # 3) No explicit instruction — decide by checking primary health
    is_running, state, inst_ok, sys_ok = get_primary_status()
    log.info("Primary running=%s state=%s inst_ok=%s sys_ok=%s", is_running, state, inst_ok, sys_ok)

    # Decide: If primary not running or not OK -> failover
    if not is_running or not inst_ok or not sys_ok:
        # perform failover
        return perform_failover(reason=f"primary_state={state},inst_ok={inst_ok},sys_ok={sys_ok}")

    # If primary healthy, and DR is running, perform failback
    # Check DR state
    try:
        desc = ec2_dr.describe_instances(InstanceIds=[DR_INSTANCE_ID])
        dr_state = desc['Reservations'][0]['Instances'][0]['State']['Name']
        log.info("DR current state (pre-failback-check): %s", dr_state)
    except Exception:
        dr_state = 'unknown'

    # If DR running and primary healthy -> failback
    if dr_state == 'running':
        return perform_failback(reason=f"primary_state={state},inst_ok={inst_ok},sys_ok={sys_ok}")

    log.info("No action required. Primary healthy and DR not running (state=%s)", dr_state)
    return {"status": "no_action", "primary_state": state, "dr_state": dr_state}
