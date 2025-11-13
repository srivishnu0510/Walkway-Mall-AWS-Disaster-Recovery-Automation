# 🌍 Walkway Mall – AWS Automated Disaster Recovery (DR) System  
## Multi-Region Failover & Failback Automation using AWS Lambda, CloudWatch, Route 53 & SNS

---

## 📘 Project Overview

This repository contains the complete implementation of an **automated Disaster Recovery (DR) solution** for the **Walkway Mall web application**, built using **Amazon Web Services (AWS)**.

The system ensures that the application remains **available 24/7**, even during server outages or regional failures.  
Using AWS automation, the solution provides:

- Automatic **Failover** → Primary EC2 → DR EC2  
- Automatic **Failback** → DR EC2 → Primary EC2  
- Health monitoring with CloudWatch  
- DNS failover using Route 53 Private Hosted Zone  
- Real-time notifications through SNS  
- Scheduled DR tests via EventBridge  
- Continuous backups using AWS Backup  

This project demonstrates a **fully self-healing, event-driven DR architecture**.

---

## 🧾 Key Features

### ✅ Automated Failover
- Detects Primary EC2 failure through CloudWatch  
- Starts the DR EC2 in another region  
- Updates DNS record automatically  
- Notifies via Amazon SNS  

### ✅ Automated Failback
- When Primary EC2 recovers  
- Stops DR EC2 to reduce cost  
- Reverts DNS back to Primary  
- Sends notification  

### ✅ Secure & Cost Efficient
- DR instance stays **stopped** (no cost) until failover  
- No domain purchase required (Route 53 Private Hosted Zone)  
- IAM least-privilege security  

### ✅ Fully Event Driven
- CloudWatch → SNS → Lambda  
- EventBridge scheduled validations  
- Route 53 Health Check for monitoring  

---

## 🏗️ Architecture Diagram
<img width="1536" height="1024" alt="architecture" src="https://github.com/user-attachments/assets/6b305cce-b316-47d4-8d1c-9b8448c263b3" />

  

               +----------------------------+
               |         End Users          |
               +-------------+--------------+
                             |
                     walkwaymall.local
                 (Route 53 Private DNS)
                             |
             +---------------+---------------+
             |                               |
      Primary EC2 (us-east-1)         DR EC2 (us-west-2)
      +-------------------+           +-------------------+
      | Running App       |           | Stopped (Idle)    |
      +---------+---------+           +---------+---------+
                |                               ^
                |                               |
       CloudWatch Alarm (Failover)               |
                |                               |
                ↓                               |
        AWS SNS Notification --------------------+
                ↓
       AWS Lambda Automation
   (Failover + Failback Logic)
                ↓
          Route 53 DNS Update
                ↓
       EventBridge Scheduled Tests

---

## 🧠 Services Used and Why

| Service | Purpose |
|---------|---------|
| **Amazon EC2** | Hosts the primary and DR servers |
| **S3** | Static website hosting & backup storage |
| **RDS** | Managed database |
| **AWS Backup** | Automated EC2/RDS backups |
| **Route 53 Private Hosted Zone** | Free DNS failover without purchasing domain |
| **CloudWatch** | Health monitoring & alarms |
| **Lambda** | Automates failover/failback |
| **SNS** | Sends notifications |
| **EventBridge** | Periodic DR tests |
| **IAM** | Least-privilege security roles |

---

## 🚀 How Automatic Failover Works

1. CloudWatch detects that **Primary EC2** is unhealthy  
2. Alarm triggers an SNS notification → Lambda  
3. Lambda executes:
   - Starts DR EC2  
   - Waits for “running” state  
   - Updates Route 53 DNS → DR IP  
   - Sends notification  
4. End-users continue accessing Walkway Mall through DR instantly  

---

## 🔄 How Automatic Failback Works

1. CloudWatch reports Primary EC2 is healthy again  
2. Lambda executes:
   - Stops DR EC2  
   - Restores DNS to Primary EIP  
   - Sends “Failback Completed” notification  

---

## 🛠️ Project Setup (Step-By-Step)

### 1️⃣ Launch Primary EC2 (us-east-1)
- Install Nginx  
- Attach Elastic IP  
- Add security group rules  
- Serve Walkway Mall application  

### 2️⃣ Launch DR EC2 (us-west-2)
- Same configuration as Primary  
- Keep it **stopped**  

### 3️⃣ Create Route 53 Private Hosted Zone
- Domain: `walkwaymall.local`  
- Create two failover A records:
  - Primary → Primary EIP  
  - Secondary → DR EIP  

### 4️⃣ Create Route 53 Health Check
- Monitors Primary EC2 HTTP port 80  

### 5️⃣ Create CloudWatch Alarm
- Metric: StatusCheckFailed_Instance  
- Alarm: ALARM → failover  
- OK → failback  

### 6️⃣ Create SNS Topic
- dr-alerts  
- Subscribe your email  

### 7️⃣ IAM Role for Lambda
Attach permissions:
- ec2  
- route53  
- sns  
- logs  

### 8️⃣ Deploy Lambda Functions
Upload the full automation code from:

### 9️⃣ Create EventBridge Rule
- rate(1 day) → Lambda  
- Automated DR readiness checks  

---

## 📂 Repository Structure

📦 WalkwayMall-DR-Automation
├── lambda/
│ ├── dr-failover & failback.py
├── infrastructure/
│ ├── IAM-policy.json
├── docs/
│ ├── architecture-diagram.png
│├── README.md ← THIS FILE


---

## 🧪 Testing Instructions
--stop primary EC2
--check alarm and health check it goes to in alarm and unhealthy
--lambda trigger DR EC2 known as failover
--theen Primary server comes back automatically DR EC2 stops known as failback

📈 Results & Outcomes

✔ Zero-downtime DR solution
✔ Fully automated failover and failback
✔ No domain purchase required
✔ Monitoring & real-time alerts
✔ Database + EC2 backups
✔ Cross-region fault tolerance
✔ Cost effective (DR instance stays stopped)
