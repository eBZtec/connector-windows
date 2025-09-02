# Certification Authority

**Follow the instruction in *docs/* directory before this**

## Configuration of service:

1. In project directory, create a virtual environment, activate it and install project requirements:
    ```
    python3 -m venv env
    source env/bin/activate
    ```

2. Make the file `midpoint-idmext-ca_server.sh` executable:

    ```
    chmod +x midpoint-idmext-ca_server.sh
    ```

3. Create a service unit file `midpoint-idmext-ca.service` in the `/etc/systemd/system/` directory. 
Replace the paths to the corresponding path file, set the "User" and "Group" with your username and set WorkingDirectory.

    ```
    [Unit]
    Description=Python Server running in virtual environment
    After=network.target

    [Service]
    Type=simple
    ExecStart=path/to/midpoint-idmext-ca_server.sh
    Restart=on-failure
    User=user
    Group=user
    WorkingDirectory=path/to/user

    [Install]
    WantedBy=multi-user.target
    ```

4. **Reload the systemd manager configuration:**

    ```
    sudo systemctl daemon-reload
    ```

5. **Enable and start the service:**

    ```
    sudo systemctl enable midpoint-idmext-ca.service
    sudo systemctl start midpoint-idmext-ca.service
    ```

6. **To restart it, do:**

    ```
    sudo systemctl restart midpoint-idmext-ca.service
    ```

7. **To check if service is running:**
    
    ```
    sudo systemctl status midpoint-idmext-ca.service
    ```
