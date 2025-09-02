# MidPoint Windows Local Account Connector

This project provides a **custom connector for MidPoint** that enables secure management of **local accounts and groups on Windows hosts**.  

It consists of **three integrated components** working together to deliver **end-to-end encryption, certificate-based trust, and provisioning capabilities**.

---

## Project Components

### 1. Java Connector (ICF-based)
- Built on **Identity Connector Framework (ICF)**.  
- Acts as the **bridge between MidPoint and Windows machines** through **ZeroMQ**.  
- Responsibilities:
  - Defines the **schema** for users and groups.  
  - Executes queries for accounts (`allAccounts`) and groups (`allGroups`).  
  - Handles `ping`/`test` operations for health checks.  
  - Translates Windows user/group attributes into MidPoint objects:
    - Users: password policy, login scripts, flags, storage limits, last login, group memberships, etc.  
    - Groups: SID, type, description, schema name  

---

### 2. Certification Authority (Python)
- Located in **`midpoint-idmext-ca`**.  
- Implements a lightweight **CA server with PostgreSQL and ZeroMQ**.  
- Responsibilities:
  - Generates and signs certificates:
    - `CA_IDMEXT` (root CA)  
    - `MIDPOINT_IDMEXT` (connector identity)  
    - Certificates for Windows hosts/users  
  - Stores certificates securely in PostgreSQL (`certificates` table).  
  - Provides ZeroMQ API for:
    - Returning CA, MidPoint, or user certificates  
    - Signing CSRs (Certificate Signing Requests)  
    - Distributing **RESOURCE_ID** and **RESOURCE_SECRET** credentials  
- Security:
  - `config.ini` is **encrypted with Fernet**.  
  - Runs as a **systemd service** for persistence.  

---

### 3. Windows Service (C#)
- Implemented as **`MidPointWindowsConnectorService`**.  
- Runs as a **Windows Service** using **.NET Core**.  
- Responsibilities:
  - **ZeroMQ server** that listens for connector requests.  
  - **Secure messaging**:
    - Messages encrypted with AES-GCM.  
    - AES keys wrapped with RSA.  
    - Data compressed with Brotli.  
  - **Certificate management**:
    - Retrieves CA and connector certificates from the CA server.  
    - Generates host CSRs and stores signed certificates in Windows Certificate Store.  
    - Auto-renews certificates before expiration.  
  - **Local account/group management**:
    - Enumerates local users (`allAccounts`).  
    - Enumerates groups (`allGroups`).  
    - Fetches users or groups by name, or groups from a given user.  
  - **Authentication**:
    - Validates `RESOURCE_ID` and `RESOURCE_SECRET` stored in Windows Registry.  
    - Values are encrypted with the machine’s private key.  

---

## End-to-End Workflow

1. **CA Service (Python)**  
   - Initializes the CA (`CA_IDMEXT`) and issues the MidPoint connector certificate (`MIDPOINT_IDMEXT`).  
   - Provides secure distribution of credentials and certificates.  

2. **Windows Service (C#)**  
   - Requests certificates from the CA.  
   - Registers machine credentials.  
   - Answers connector queries (users, groups, memberships).  

3. **Connector (Java)**  
   - Connects to Windows Service via ZeroMQ.  
   - Executes provisioning/search requests.  
   - Relays results back to MidPoint.  

---

## Technology Stack

- **Java** → ICF, Unirest, Brotli4j  
- **Python** → cryptography, psycopg2, ZeroMQ  
- **.NET (C#)** → NetMQ, BouncyCastle, DirectoryServices  
- **PostgreSQL** → Certificate storage  

---

## Deployment Overview

- **Linux (CA Server)**  
  - Runs the Python CA service (`midpoint-idmext-ca`).  
  - Manages PostgreSQL and certificates.  

- **Windows (Target Machines)**  
  - Runs the `MidPointWindowsConnectorService` as a Windows Service.  
  - Manages local users/groups and handles encrypted communication.  

- **MidPoint (Identity Manager)**  
  - Uses the **Java connector** to integrate with Windows machines.  
