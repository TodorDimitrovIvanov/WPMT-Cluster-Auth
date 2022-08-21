import json

import requests
import uvicorn
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import mysql.connector
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

app = FastAPI()

__master_url__ = "https://master.wpmt.tech"

__cluster_name__ = "cluster-eu01.wpmt.tech"
__cluster_url__ = "http://cluster-eu01.wpmt.tech"
__cluster_logger_url__ = "http://cluster-eu01.wpmt.tech/log/save"
__cluster_locale__ = "EU"
__cluster_user_count__ = None
__app_headers__ = {
    'Host': 'cluster-eu01.wpmt.org',
    'User-Agent': 'WPMT-Auth/1.0',
    'Referer': 'http://cluster-eu01.wpmt.org/auth/verify',
    'Content-Type': 'application/json'
}

# TODO: Remove this code once the K8S implementation is completed
# Source: https://stackoverflow.com/questions/60343474/how-to-get-secret-environment-variables-implemented-by-kubernetes-into-python
# This variable is set by Kubernetes via the "secretGenerator.yaml" file
__mysql_host__ = "localhost"
__mysql_db__ = "cluster_eu01"
__mysql_user__ = "cluser_eu01_user"
__mysql_pass__ = "kP6hE3zE7aJ7nQ6i"


def mysql_details_get():
    # TODO: Here we should retrieve the global MySQL details that are set in Kubernetes
    # TODO: And apply them to the global variables above
    pass


def key_to_utf8(s: bytes):
    return str(s, 'utf-8')


def send_to_logger(err_type, message, client_id, client_email):
    # TODO: Find a way to get the user's IP address and add it to the message
    global __app_headers__
    body = {
        "client_id": client_id,
        "email": client_email,
        "type": err_type,
        "message": message
    }
    send_request = requests.post(__cluster_logger_url__, data=json.dumps(body), headers=__app_headers__)


def cluster_user_verify(email, encrypted_mail):
    # Source: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#decryption
    ''' Whenever the client tries to sign in with his email and public_key
        The WPMT User API encrypts his email address using the public_key
        And then sends both encrypted and non-encrypted email addresses to the Cluster API
        Once the Cluster API receives the POST request it then searches for the email address in the Cluster DB
        If such email address is found we then retrieve the user's private_key
        And finally we use the client's private_key to decrypt the encrypted email address that was sent earlier
        And if matches what we have in store we return a 200 OK to the WPMT User API'''
    if None not in [email, encrypted_mail]:
        # Here email is the string that the client inputs via the WPMT Client
        # And encrypted mail is the result of using the client's public_key which he also provides in the WPMT Client
        try:
            connection = mysql.connector.connect(
                host=__mysql_host__,
                database=__mysql_db__,
                user=__mysql_user__,
                passwd=__mysql_pass__
            )
            if connection.is_connected():
                cursor = connection.cursor()
                mysql_query = "SELECT client_email, client_priv_key, client_id FROM users WHERE client_email = %s"
                mysql_data = email
                cursor.execute(mysql_query, (mysql_data,))
                # This should return a list of the results - the email (1st), the priv_key (2nd) and the client_id (3rd)
                # All elements of the list should be strings
                sql_result = cursor.fetchall()

                # First we clean up the private key by removing new lines
                raw_key = sql_result[0][1].replace('\\n', '\n')

                # Here we transform the string key into a bytes object
                # As it is required by the load_pem_private_key function
                encoded_key = raw_key.encode()
                private_key = load_pem_private_key(
                    encoded_key,
                    backend=default_backend(),
                    password=None
                )

                # Here we decrypt the message that was sent by the WPMT Client
                # First we convert it from hex to bytes type
                bytes_message = bytes.fromhex(encrypted_mail)
                decrypted_mail = private_key.decrypt(
                    bytes_message,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                if key_to_utf8(decrypted_mail) == sql_result[0][0]:
                    log_message = "[Cluster][Access][Auth][" + sql_result[0][2] + "]" + "[200]" # + IP ADDRESS
                    send_to_logger("info", log_message, sql_result[0][2], sql_result[0][0])
                    return True
                else:
                    log_message = "[Cluster][Access][Auth][" + sql_result[0][2] + "]" + "[403]"  # + IP ADDRESS
                    send_to_logger("info", log_message, sql_result[0][2], sql_result[0][0])
                    return False
        except mysql.connector.Error as e:
            message = "[Cluster][Error][DB][01][" + sql_result[0][2] + "]: Error while starting the K8S MySQL Connection! Full error: [" + str(e) + "]."
            send_to_logger("error", message, sql_result[0][2], sql_result[0][0])
            return False


class UserVerification(BaseModel):
    email: str
    encrypted_email: str


@app.post("/auth/verify", status_code=200)
def user_verify(user_verify: UserVerification):
    data_dic = user_verify.dict()
    # TODO: Add input verification and error handling
    if cluster_user_verify(data_dic['email'], data_dic['encrypted_email']):
        # Here we should send a 200 OK response to the WPMT User API
        return{
            "Response": "Success"
        }
    else:
        # Here we should send a 403 Forbidden response to the WPMT User API
        return{
            "Response": "Failure"
        }


if __name__ == '__main__':
    uvicorn.run(app, host='0.0.0.0', port=6901)

