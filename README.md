## List Linux Users

This script collects information about all Linux users on the system, providing a JSON-formatted output for integration with security tools like OSSEC/Wazuh.

### Overview

The `List Linux Users` script enumerates all users, collecting details such as username, full name, home directory, group memberships, last login, and password status. Output is formatted as JSON for active response workflows.

### Script Details

#### Core Features

1. **User Enumeration**: Lists all users with UID >= 0, skipping obvious service accounts.
2. **Metadata Collection**: Collects username, full name, home directory, groups, last login, password required/expired status.
3. **JSON Output**: Generates a structured JSON report for integration with security tools.
4. **Logging Framework**: Provides detailed logs for script execution.
5. **Log Rotation**: Implements automatic log rotation to manage log file size.

### How the Script Works

#### Command Line Execution
```bash
./ListLinuxUsers
```

#### Parameters

| Parameter | Type | Default Value | Description |
|-----------|------|---------------|-------------|
| `ARLog`   | string | `/var/ossec/active-response/active-responses.log` | Path for active response JSON output |
| `LogPath` | string | `/tmp/ListLinuxUsers-script.log` | Path for detailed execution logs |
| `LogMaxKB` | int | 100 | Maximum log file size in KB before rotation |
| `LogKeep` | int | 5 | Number of rotated log files to retain |

### Script Execution Flow

#### 1. Initialization Phase
- Clears the active response log file
- Rotates the detailed log file if it exceeds the size limit
- Logs the start of the script execution

#### 2. User Collection
- Enumerates all users (excluding obvious service accounts)
- Collects metadata for each user

#### 3. JSON Output Generation
- Formats user details into a JSON array
- Writes the JSON result to the active response log

### JSON Output Format

#### Example Response
```json
{
  "timestamp": "2025-07-18T10:30:45.123Z",
  "host": "HOSTNAME",
  "action": "list_linux_users",
  "users": [
    {
      "username": "root",
      "fullname": "root",
      "home": "/root",
      "groups": "root",
      "lastlogon": "Thu Jul 18 10:30:45 2025",
      "password_required": true,
      "password_expired": false
    },
    {
      "username": "jane",
      "fullname": "Jane Doe",
      "home": "/home/jane",
      "groups": "jane,sudo",
      "lastlogon": "Thu Jul 18 09:15:00 2025",
      "password_required": true,
      "password_expired": false
    }
  ],
  "copilot_soar": true
}
```

### Implementation Guidelines

#### Best Practices
- Run the script with appropriate permissions to access user and shadow information
- Validate the JSON output for compatibility with your security tools
- Test the script in isolated environments

#### Security Considerations
- Ensure minimal required privileges
- Protect the output log files

### Troubleshooting

#### Common Issues
1. **Permission Errors**: Ensure the script has privileges to read `/etc/passwd` and `/etc/shadow`
2. **Missing Data**: Some users may not have last login information
3. **Log File Issues**: Check write permissions

#### Debugging
Enable verbose logging:
```bash
VERBOSE=1 ./ListLinuxUsers
```

### Contributing

When modifying this script:
1. Maintain the user metadata collection and JSON output structure
2. Follow Shell scripting best practices
3. Document any additional functionality
4. Test thoroughly in isolated environments
