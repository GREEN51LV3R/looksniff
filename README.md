# LOOKSNIFF 
## Description

LOOKSNIFF is a packet sniffer written in Python that captures network packets and extracts useful information such as HTTP requests and login details. It offers options to log captured data, send alerts, and print raw packets.

## Features

- Capture and log HTTP requests and login information.
- Option to store logs in a file.
- Option to receive email and desktop notifications for sensitive information.
- Display network interfaces and their IP/MAC addresses.

## Warning

**This tool is intended for educational purposes only. Unauthorized use of this tool to monitor network traffic without permission is illegal and unethical. The author is not responsible for any damage caused by the use or misuse of this tool. Use at your own risk.** 

## Requirements

- Python `3.x`
- Required Python libraries listed in `requirements.txt`


## Installation

1. Clone the repository:

    ```sh
    git clone https://github.com/GREEN51LV3R/looksniff.git
    cd looksniff
    ```

2. Install the required Python libraries:

    ```sh
    pip install -r requirements.txt
    ```


## Usage

1. Run the script:

    ```sh
    sudo python looksniff.py
    ```

2. Follow the prompts to choose options for logging, alerting, and network interface selection.

## Configuration

### Email Alerts

To enable email alerts, you need to configure your email settings in the script:

```python
def send_email_alert(message):
    try:
        from_address = "your_email@example.com"
        to_address = "recipient_email@example.com"
        subject = "Sensitive Information Detected"
        msg = MIMEText(message)
        msg["Subject"] = subject
        msg["From"] = from_address
        msg["To"] = to_address

        server = smtplib.SMTP("smtp.example.com", 587)
        server.starttls()
        server.login("your_email@example.com", "your_password")
        server.sendmail(from_address, to_address, msg.as_string())
        server.quit()
    except Exception as e:
        print(f"Failed to send email: {e}")
```
Replace the placeholder values with your actual email configuration.

### Desktop Notifications
Desktop notifications are enabled using the `plyer` library. Make sure it is installed and configured correctly.

## Troubleshooting

#### ModuleNotFoundError
If you encounter a `ModuleNotFoundError`, make sure all required libraries are installed. Run the following command to install them:

```

pip install -r requirements.txt

```
#### Permission Issues
Ensure you have the necessary permissions to run the script and access network interfaces. You may need to run the script as an administrator or root user.

#### Email Alerts Not Sending
Verify your email configuration in the script.
Ensure you are using the correct SMTP server and port.
Check your email account for security settings that may block less secure apps.

## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

