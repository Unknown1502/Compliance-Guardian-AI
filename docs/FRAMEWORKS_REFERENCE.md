# Compliance Frameworks Reference

## Overview

This document provides detailed information about the three compliance frameworks supported by Compliance Guardian AI: GDPR, HIPAA, and PCI-DSS.

---

## Table of Contents

1. [GDPR - General Data Protection Regulation](#gdpr)
2. [HIPAA - Health Insurance Portability and Accountability Act](#hipaa)
3. [PCI-DSS - Payment Card Industry Data Security Standard](#pci-dss)
4. [Framework Comparison](#framework-comparison)
5. [Violation Matrix](#violation-matrix)

---

## GDPR

### Overview

**Full Name**: General Data Protection Regulation 
**Jurisdiction**: European Union 
**Effective Date**: May 25, 2018 
**Scope**: Any organization processing EU citizen data 
**Maximum Fines**: €20 million or 4% of annual global turnover

### Key Principles

#### 1. Lawfulness, Fairness, and Transparency
- Legal basis for processing
- Clear communication with data subjects
- No hidden data collection

#### 2. Purpose Limitation
- Collect data only for specified purposes
- Cannot repurpose without consent

#### 3. Data Minimization
- Collect only necessary data
- Avoid excessive data collection

#### 4. Accuracy
- Keep data up-to-date
- Allow corrections

#### 5. Storage Limitation
- Delete data when no longer needed
- Define retention periods

#### 6. Integrity and Confidentiality
- Secure data processing
- Prevent unauthorized access

### Protected Data Types

**Personally Identifiable Information (PII)**:
- Name
- Email address
- Phone number
- Physical address
- IP address
- Cookie identifiers
- Location data

**Special Category Data**:
- Racial or ethnic origin
- Political opinions
- Religious beliefs
- Trade union membership
- Genetic data
- Biometric data
- Health data
- Sexual orientation

### GDPR Rights

1. **Right to Access**: Users can request their data
2. **Right to Rectification**: Correct inaccurate data
3. **Right to Erasure**: "Right to be forgotten"
4. **Right to Restriction**: Limit processing
5. **Right to Data Portability**: Transfer data between services
6. **Right to Object**: Stop certain processing
7. **Rights Related to Automated Decision Making**: Human review of automated decisions

### Technical Requirements

#### Encryption
```python
# [[]] GDPR Compliant
from cryptography.fernet import Fernet

def store_pii(email, name):
 cipher = Fernet(key)
 encrypted_email = cipher.encrypt(email.encode())
 encrypted_name = cipher.encrypt(name.encode())
 db.save(encrypted_email, encrypted_name)
```

#### Consent Management
```python
# [[]] GDPR Compliant
def collect_email(email, consent):
 if not consent:
 raise ValueError("Consent required for email processing")

 if consent.marketing:
 subscribe_newsletter(email)

 log_consent(email, consent, timestamp=now())
```

#### Data Deletion
```python
# [[]] GDPR Compliant
def delete_user_data(user_id):
 # Delete from all systems
 db.delete_user(user_id)
 cache.delete_user(user_id)
 analytics.anonymize_user(user_id)
 backups.mark_for_deletion(user_id)

 log_deletion(user_id, timestamp=now())
```

### Common GDPR Violations

| Violation | Description | Severity | Example |
|-----------|-------------|----------|---------|
| Unencrypted PII | Storing PII without encryption | Critical | `email = "user@example.com"` in plain text |
| No Consent | Processing without user consent | High | Marketing emails without opt-in |
| Excessive Retention | Keeping data too long | High | User data stored indefinitely |
| No Deletion Capability | Cannot delete user data | High | No delete account function |
| Missing Data Portability | Cannot export user data | Medium | No data export feature |
| No Breach Notification | Not informing users of breaches | Critical | Data breach without notification |

### GDPR Checklist

- [ ] Encrypt all PII at rest
- [ ] Encrypt all PII in transit (HTTPS/TLS)
- [ ] Implement consent management
- [ ] Provide data access functionality
- [ ] Implement data deletion ("right to be forgotten")
- [ ] Enable data portability (export)
- [ ] Define data retention periods
- [ ] Document data processing activities
- [ ] Implement breach notification procedures
- [ ] Appoint Data Protection Officer (if required)

---

## HIPAA

### Overview

**Full Name**: Health Insurance Portability and Accountability Act 
**Jurisdiction**: United States 
**Effective Date**: April 14, 2003 
**Scope**: Healthcare providers, health plans, healthcare clearinghouses 
**Maximum Fines**: $50,000 per violation, up to $1.5 million per year

### Protected Health Information (PHI)

**Identifiers that make data PHI**:
- Names
- Geographic subdivisions smaller than state
- Dates (birth, admission, discharge, death)
- Phone numbers
- Fax numbers
- Email addresses
- Social Security numbers
- Medical record numbers
- Health plan beneficiary numbers
- Account numbers
- Certificate/license numbers
- Vehicle identifiers
- Device identifiers
- URLs
- IP addresses
- Biometric identifiers
- Photos
- Any other unique identifying number

**Note**: If data contains ANY of these identifiers AND relates to health, it's PHI.

### HIPAA Rules

#### Privacy Rule
- Protects PHI privacy
- Limits use and disclosure
- Gives patients rights over their health information

#### Security Rule
- Administrative safeguards
- Physical safeguards
- Technical safeguards

#### Breach Notification Rule
- Notify individuals within 60 days
- Notify HHS
- Media notification (for large breaches)

### Technical Safeguards

#### 1. Access Control
```python
# [[]] HIPAA Compliant
@require_authentication
@require_role(['doctor', 'nurse', 'admin'])
@audit_log
def get_patient_record(patient_id):
 if not has_patient_access(current_user, patient_id):
 raise PermissionDenied("Not authorized to access this patient")

 return db.get_patient(patient_id)
```

#### 2. Encryption
```python
# [[]] HIPAA Compliant
def store_patient_data(patient_data):
 # Encrypt PHI
 encrypted_data = encrypt_aes256(patient_data)

 # Store encrypted
 db.save(encrypted_data)

 # Audit log
 audit.log(f"Stored PHI for patient {patient_data['id']}")
```

#### 3. Audit Logging
```python
# [[]] HIPAA Compliant
def access_phi(user_id, patient_id, action):
 # Log every access
 audit_log.record({
 'timestamp': now(),
 'user_id': user_id,
 'patient_id': patient_id,
 'action': action,
 'ip_address': get_client_ip(),
 'session_id': get_session_id()
 })

 # Keep logs for 6 years (HIPAA requirement)
```

#### 4. Multi-Factor Authentication
```python
# [[]] HIPAA Compliant
@app.route('/login', methods=['POST'])
def login():
 username = request.form['username']
 password = request.form['password']

 # First factor: Password
 if not verify_password(username, password):
 return "Invalid credentials", 401

 # Second factor: MFA code
 if not verify_mfa_code(username, request.form['mfa_code']):
 return "Invalid MFA code", 401

 return create_session(username)
```

### Common HIPAA Violations

| Violation | Description | Severity | Example |
|-----------|-------------|----------|---------|
| Unencrypted PHI | PHI stored without encryption | Critical | `ssn = "123-45-6789"` in plain text |
| No Access Controls | Anyone can access patient data | Critical | Public database access |
| No Audit Logs | Not logging PHI access | High | No record of who viewed patient data |
| No MFA | Single-factor authentication | High | Password-only login |
| Missing BAAs | No Business Associate Agreements | High | Third-party services without contracts |
| No Breach Notification | Not reporting breaches | Critical | Data breach unreported |

### HIPAA Checklist

- [ ] Encrypt all PHI at rest (AES-256)
- [ ] Encrypt all PHI in transit (TLS 1.2+)
- [ ] Implement role-based access control
- [ ] Enable multi-factor authentication
- [ ] Implement audit logging (6-year retention)
- [ ] Conduct risk assessments
- [ ] Sign Business Associate Agreements
- [ ] Train workforce on HIPAA
- [ ] Implement breach notification procedures
- [ ] Perform regular security audits
- [ ] Establish incident response plan
- [ ] Implement automatic log-off

---

## PCI-DSS

### Overview

**Full Name**: Payment Card Industry Data Security Standard 
**Jurisdiction**: Global (all payment card transactions) 
**Version**: PCI-DSS 4.0 (March 2022) 
**Scope**: Any organization storing, processing, or transmitting cardholder data 
**Maximum Fines**: $5,000-$100,000 per month + loss of card processing privileges

### Cardholder Data

**Primary Account Number (PAN)**:
- 16-digit card number
- **MUST** be protected
- **CAN** be stored if encrypted

**Sensitive Authentication Data (SAD)**:
- Full magnetic stripe data
- CAV2/CVC2/CVV2/CID codes
- PINs/PIN blocks
- **MUST NEVER** be stored after authorization

**Additional Cardholder Data**:
- Cardholder name
- Service code
- Expiration date
- **CAN** be stored if needed

### The 12 Requirements

#### 1. Install and Maintain a Firewall
- Network segmentation
- Firewall rules
- DMZ for public-facing systems

#### 2. Do Not Use Vendor Defaults
- Change default passwords
- Remove default accounts
- Disable unnecessary services

#### 3. Protect Stored Cardholder Data
- Encrypt PAN
- **NEVER store CVV/CVC**
- Mask PAN when displayed

#### 4. Encrypt Transmission of Cardholder Data
- TLS 1.2+ for transmission
- Strong cryptography
- Secure protocols only

#### 5. Protect Against Malware
- Anti-virus software
- Keep definitions up-to-date
- Regular scans

#### 6. Develop Secure Systems and Applications
- Secure development lifecycle
- Regular security testing
- Vulnerability management

#### 7. Restrict Access by Business Need
- Role-based access control
- Least privilege principle
- Regular access reviews

#### 8. Identify and Authenticate Access
- Unique user IDs
- Strong authentication
- Multi-factor for remote access

#### 9. Restrict Physical Access
- Physical security controls
- Visitor logs
- Secure storage

#### 10. Track and Monitor All Access
- Audit logging
- Log reviews
- Time synchronization

#### 11. Regularly Test Security
- Quarterly network scans
- Annual penetration tests
- Vulnerability scanning

#### 12. Maintain an Information Security Policy
- Security policy
- Regular updates
- Employee acknowledgment

### Technical Requirements

#### Encryption Requirements

```python
# [[]] PCI-DSS Compliant
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def store_card_data(pan, cardholder_name, exp_date):
 # Encrypt PAN with AES-256
 encrypted_pan = encrypt_aes256(pan)

 # Store encrypted PAN + plain name/exp
 db.save({
 'pan': encrypted_pan, # Encrypted
 'name': cardholder_name, # Plain text OK
 'exp': exp_date # Plain text OK
 })

 # [] NEVER store CVV
 # cvv = "123" # VIOLATION
```

#### CVV Storage Prohibition

```python
# [] PCI-DSS VIOLATION
def process_payment_wrong(card_number, cvv, exp_date):
 payment = {
 'card': card_number,
 'cvv': cvv, # [] NEVER STORE CVV
 'exp': exp_date
 }
 db.save(payment) # VIOLATION

# [[]] PCI-DSS Compliant
def process_payment_correct(card_number, cvv, exp_date):
 # Use CVV only for authorization
 auth_response = payment_gateway.authorize({
 'card': card_number,
 'cvv': cvv, # Used once, not stored
 'exp': exp_date
 })

 # Store only token
 db.save({
 'token': auth_response.token,
 'last4': card_number[-4:],
 'exp': exp_date
 })
```

#### Tokenization

```python
# [[]] PCI-DSS Compliant (Recommended)
def tokenize_card(card_number, cvv, exp_date):
 # Send to payment gateway for tokenization
 response = stripe.Token.create(
 card={
 'number': card_number,
 'exp_month': exp_date.month,
 'exp_year': exp_date.year,
 'cvc': cvv
 }
 )

 # Store only token (no PAN, no CVV)
 db.save({
 'token': response.id,
 'last4': response.card.last4,
 'brand': response.card.brand
 })

 return response.id
```

### Common PCI-DSS Violations

| Violation | Description | Severity | Example |
|-----------|-------------|----------|---------|
| CVV Storage | Storing CVV/CVC codes | Critical | `cvv = "123"` in database |
| Unencrypted PAN | Storing card numbers in plain text | Critical | `card = "4111111111111111"` |
| Weak Encryption | Using outdated encryption | High | MD5 or SHA-1 hashing |
| No Network Segmentation | Card data in same network as other systems | High | Flat network architecture |
| Missing Audit Logs | Not logging card data access | High | No access tracking |
| Default Passwords | Using vendor defaults | Medium | Admin password is "admin" |
| No Vulnerability Scans | Not scanning for vulnerabilities | Medium | No quarterly scans |

### PCI-DSS Compliance Levels

| Level | Transaction Volume | Requirements |
|-------|-------------------|--------------|
| **Level 1** | 6M+ transactions/year | Quarterly scans, annual audit |
| **Level 2** | 1M-6M transactions/year | Quarterly scans, annual SAQ |
| **Level 3** | 20K-1M e-commerce/year | Quarterly scans, annual SAQ |
| **Level 4** | <20K e-commerce/year | Quarterly scans, annual SAQ |

### PCI-DSS Checklist

- [ ] **NEVER store CVV/CVC codes**
- [ ] Encrypt all stored PANs (AES-256)
- [ ] Use TLS 1.2+ for card data transmission
- [ ] Implement network segmentation
- [ ] Enable firewall protection
- [ ] Use strong access controls
- [ ] Implement audit logging
- [ ] Mask PAN when displayed (show only last 4)
- [ ] Conduct quarterly vulnerability scans
- [ ] Perform annual penetration tests
- [ ] Train employees on PCI-DSS
- [ ] Maintain security policy
- [ ] Consider tokenization to reduce scope

---

## Framework Comparison

| Aspect | GDPR | HIPAA | PCI-DSS |
|--------|------|-------|---------|
| **Jurisdiction** | EU | US | Global |
| **Focus** | Data Privacy | Healthcare | Payment Security |
| **Data Type** | PII | PHI | Payment Card Data |
| **Max Fine** | €20M or 4% revenue | $1.5M/year | $100K/month + loss of processing |
| **Encryption** | Required | Required | Required |
| **Audit Logs** | Recommended | Required (6 years) | Required |
| **Breach Notification** | 72 hours | 60 days | Immediate |
| **Consent** | Explicit | Not required | Not required |
| **Data Deletion** | Required | Not required | Not addressed |
| **Compliance Level** | Binary (compliant/not) | Binary | 4 levels |

---

## Violation Matrix

### Severity Classification

| Severity | GDPR | HIPAA | PCI-DSS |
|----------|------|-------|---------|
| **Critical** | Unencrypted PII, No breach notification | Unencrypted PHI, Public access to patient data | CVV storage, Unencrypted PAN |
| **High** | Missing consent, No data deletion | No audit logs, No MFA | Weak encryption, No network segmentation |
| **Medium** | Excessive retention, Missing portability | Missing BAAs, Insufficient training | Default passwords, No vulnerability scans |
| **Low** | Documentation gaps, Minor process issues | Minor procedural gaps | Documentation issues |

### Overlap Between Frameworks

```
 ┌─────────────────────────────────────┐
 │ │
 │ GDPR │
 │ │
 │ ┌──────────────────────┐ │
 │ │ │ │
 ┌────┼─────┤ HIPAA │ │
 │ │ │ │ │
 │ │ │ ┌──────────┐ │ │
 │ │ └────┤ │──────┘ │
 │ │ │ PCI-DSS │ │
 │ └──────────┤ │──────────────┘
 │ └──────────┘
 │
 └─ Common Requirements:
 • Encryption
 • Access Controls
 • Audit Logging
 • Breach Notification
 • Security Training
```

### Multi-Framework Violations

Some violations affect multiple frameworks:

| Violation | GDPR | HIPAA | PCI-DSS |
|-----------|------|-------|---------|
| No encryption | [] | [] | [] |
| Weak access controls | [] | [] | [] |
| Missing audit logs | [] | [] | [] |
| No MFA | - | [] | [] |
| No data deletion | [] | - | - |
| CVV storage | - | - | [] |
| No consent | [] | - | - |

---

## Best Practices Across All Frameworks

### 1. Encryption Everywhere

```python
# [[]] Universal Best Practice
def store_sensitive_data(data):
 encrypted = encrypt_aes256(data)
 db.save(encrypted)
```

### 2. Access Controls

```python
# [[]] Universal Best Practice
@require_authentication
@require_authorization
@audit_log
def access_sensitive_data(data_id):
 return db.get(data_id)
```

### 3. Audit Logging

```python
# [[]] Universal Best Practice
def log_access(user, resource, action):
 audit_log.record({
 'timestamp': now(),
 'user': user,
 'resource': resource,
 'action': action,
 'ip': get_client_ip()
 })
```

### 4. Regular Assessments

- **Weekly**: Monitor logs and metrics
- **Monthly**: Review access controls
- **Quarterly**: Vulnerability scans
- **Annually**: Full compliance audit

### 5. Employee Training

- Initial training for all employees
- Annual refresher courses
- Role-specific training
- Document training completion

---

## Quick Reference Cheat Sheet

### GDPR Quick Check
```bash
[ ] Encrypt PII
[ ] Obtain consent
[ ] Enable data deletion
[ ] Implement data export
[ ] Define retention periods
```

### HIPAA Quick Check
```bash
[ ] Encrypt PHI
[ ] Implement access controls
[ ] Enable audit logging
[ ] Require MFA
[ ] Sign BAAs
```

### PCI-DSS Quick Check
```bash
[ ] NEVER store CVV
[ ] Encrypt PANs
[ ] Use TLS 1.2+
[ ] Segment network
[ ] Conduct vulnerability scans
```

---

## Additional Resources

### Official Standards
- [GDPR Official Text](https://gdpr.eu/)
- [HIPAA Guidance](https://www.hhs.gov/hipaa)
- [PCI-DSS Standards](https://www.pcisecuritystandards.org/)

### Tools and Libraries
- **Encryption**: `cryptography` (Python), `crypto-js` (JavaScript)
- **Audit Logging**: AWS CloudTrail, Splunk, ELK Stack
- **Access Control**: AWS IAM, Auth0, Okta
- **Scanning**: Nessus, Qualys, AWS Inspector

### Certification Programs
- GDPR: CIPP/E (Certified Information Privacy Professional)
- HIPAA: CHC (Certified HIPAA Compliance)
- PCI-DSS: PCI-DSS QSA (Qualified Security Assessor)

---

**Stay Compliant! **

Remember: Compliance is an ongoing process, not a one-time achievement.
