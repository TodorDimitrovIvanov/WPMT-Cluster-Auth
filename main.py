import uvicorn
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
        try:
            connection = mysql.connector.connect(
                host=__mysql_host__,
                database=__mysql_db__,
                user=__mysql_user__,
                passwd=__mysql_pass__
            )
            if connection.is_connected():
                cursor = connection.cursor()
                mysql_query = "SELECT email, priv_key FROM users WHERE email = %s"
                mysql_data = email
                cursor.execute(mysql_query, (mysql_data,))
                # This should return a list of the results - the email (1st) and the priv_key (2nd)
                priv_key = cursor.fetchall()

                decrypted_mail = priv_key[1].decrypt(
                    encrypted_mail,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256,
                        label=None
                    )
                )
                # Not sure what type the "decrypted_mail" var will be
                if decrypted_mail == priv_key[0]:
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


@app.post("/user/verify")
def user_verify(user_verify: UserVerification):
    data_dic = user_verify.dict()
    if cluster_user_verify(data_dic['email'], data_dic['encrypted_mail']):
        # Here we should send a 200 OK response to the WPMT User API
        pass
    else:
        # Here we should send a 403 Forbidden response to the WPMT User API
        pass


if __name__ == '__main__':
    uvicorn.run(app, host='localhost', port=6901)

