import base64

import uvicorn
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from fastapi import FastAPI
from pydantic import BaseModel
import mysql.connector
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

app = FastAPI()

__master_url__ = "https://master.wpmt.tech"

__cluster_name__ = "cluster-eu01.wpmt.tech"
__cluster_url__ = "https://cluster-eu01.wpmt.tech"
__cluster_locale__ = "EU"
__cluster_user_count__ = None

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
                mysql_query = "SELECT client_email, client_priv_key FROM users WHERE client_email = %s"
                mysql_data = email
                cursor.execute(mysql_query, (mysql_data,))
                # This should return a list of the results - the email (1st) and the priv_key (2nd)
                # Both elements of the list should be strings
                sql_result = cursor.fetchall()
                print("SQL Result: ", sql_result[0][0], "Type: ", type(sql_result[0][0]))

                # First we clean up the private key by removing new lines
                raw_key = sql_result[0][1]#.replace('\n', '')

                # Here we transform the string key into a bytes object
                # As it is required by the load_pem_private_key function
                encoded_key = raw_key.encode()
                private_key = load_pem_private_key(
                    encoded_key,
                    backend=default_backend(),
                    password=None
                )

                # Here we decrypt the message that was sent by the WPMT Client
                # Note: The decrypted_mail result should be of type bytes
                decrypted_mail = private_key.decrypt(
                    # We decode the base64 encoded message
                    base64.b64decode(encrypted_mail),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                print("MySQL Fetched Email: ", sql_result[0][0], "Type: ", type(sql_result[0][0]))
                print("MySQL Fetched Key: ", sql_result[0][1], "Type: ", type(sql_result[0][1]))
                print("Original Email Sent: ", email, "Type: ", type(email))
                print("Original Message Sent: ", encrypted_mail, "Type: ", type(encrypted_mail))
                print("Decrypted Message: ", key_to_utf8(decrypted_mail), "Type: ", type(key_to_utf8(decrypted_mail)))

                # To compare the
                if key_to_utf8(decrypted_mail) == sql_result[0][0]:
                    # TODO: Send to the Logger
                    return True
                else:
                    # TODO: Send to the Logger
                    return False

        except mysql.connector.Error as e:
            # TODO: Send to the Logger
            print("[Cluster][DB][Err][01]: Error while starting the K8S MySQL Connection. Error: [", e, "].")
        finally:
            pass


class UserVerification(BaseModel):
    email: str
    encrypted_email: str


@app.post("/auth/verify")
def user_verify(user_verify: UserVerification):
    data_dic = user_verify.dict()
    # TODO: Add input verification and error handling
    if cluster_user_verify(data_dic['email'], data_dic['encrypted_email']):
        # Here we should send a 200 OK response to the WPMT User API
        return{
            "Response": "Success!"
        }
    else:
        # Here we should send a 403 Forbidden response to the WPMT User API
        return {
            "Response": "Access Denied!"
        }


if __name__ == '__main__':
    uvicorn.run(app, host='localhost', port=6901)

