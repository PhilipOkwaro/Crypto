import os
from twilio.rest import Client
from decouple import config, UndefinedValueError


account_sid = os.getenv('TWILIO_ACCOUNT_SID', '')
auth_token = os.getenv('TWILIO_AUTH_TOKEN', '')
twilio_phone_number = os.getenv('TWILIO_PHONE_NUMBER', '')


print(f"TWILIO_PHONE_NUMBER: {twilio_phone_number}")  # Debugging statement
print(f"TWILIO_ACCOUNT_SID: {account_sid}")           # Debugging statement
print(f"TWILIO_AUTH_TOKEN: {auth_token}")             # Debugging statement

def send_text_msg(destination: str, msg: str):
    if not (account_sid and auth_token and twilio_phone_number):
        raise ValueError("Twilio credentials are not properly set.")

    client = Client(account_sid, auth_token)

    message = client.messages.create(
        body=msg,
        from_=twilio_phone_number,
        to=destination
    )

# test
if __name__ == '__main__':
    send_text_msg('your_text_account_number_here', 'Hello from Python!')
