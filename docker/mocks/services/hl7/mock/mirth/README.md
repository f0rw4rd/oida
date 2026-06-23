# Mirth Connect Configuration

## Access

- **Admin Console**: https://localhost:8443
- **Default Credentials**: admin / admin

## HL7 MLLP Ports

After configuring channels:
- Port 6661: ADT messages
- Port 6662: ORU messages
- Port 6663: ORM messages

## Initial Setup

1. Start the containers:
   ```bash
   docker-compose up -d mirth-db mirth-connect
   ```

2. Wait for Mirth to start (check health):
   ```bash
   docker-compose ps mirth-connect
   ```

3. Access admin console at https://localhost:8443

4. Create HL7 Listener channels:
   - Channel 1: ADT Listener on port 6661
   - Channel 2: ORU Listener on port 6662
   - Channel 3: ORM Listener on port 6663

## Channel Configuration Script

You can use the Mirth REST API to deploy channels after startup:

```bash
# Get auth token
curl -k -X POST https://localhost:8443/api/users/_login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin"
```

## Security Testing Notes

Mirth Connect provides realistic HL7 testing:
- Full HL7 v2.x message parsing
- Proper ACK/NAK responses
- Message routing and transformation
- Audit logging
