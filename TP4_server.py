"""\
GLO-2000 Travail pratique 4 - Serveur 2025
Noms et numéros étudiants:
- Samuel Blanchette
- Wiseley
- Jacob Provencher 111 272 785
"""

import hashlib
import hmac
import json
import os
import select
import socket
import sys
import re
import logging

import glosocket
import gloutils


logging.basicConfig(
    format='%(asctime)s %(levelname)s: %(message)s',
    level=logging.INFO
)
logger = logging.getLogger()
logger.disabled = False


class Server:
    """Serveur mail @glo2000.ca 2025."""

    def __init__(self) -> None:
        """
        Prépare le socket du serveur `_server_socket`
        et le met en mode écoute.

        Prépare les attributs suivants:
        - `_client_socs` une liste des sockets clients.
        - `_logged_users` un dictionnaire associant chaque
            socket client à un nom d'utilisateur.

        S'assure que les dossiers de données du serveur existent.
        """
        self._localhost = "127.0.0.1"

        # Cree le socket en mode IPv4 et TCP
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Mets en ecoute sur le port `APP_PORT`
        try:
            self._server_socket.bind((self._localhost, gloutils.APP_PORT))
        except OSError:
            sys.exit(1)
        self._server_socket.listen()

        # Prepare une liste vide pour les sockets clients connectes
        self._client_socs: list[socket.socket] = []

        # Prepare un dictionnaire vide qui associe les sockets clients
        # authentifies a leur nom d'utilisateur
        self._logged_users: dict[socket.socket, str] = {}


        # [TODO] S'assurer que le dossier SERVER_DATA_DIR existe et
        # et qu'il contient le SERVER_LOST_DIR.
        # Les creer sinon.
        logger.info("On s'assure que le dossier `SERVER_DATA_DIR`.")

    def cleanup(self) -> None:
        """Ferme toutes les connexions résiduelles."""
        for client_soc in self._client_socs:
            client_soc.close()
        self._server_socket.close()

    def _accept_client(self) -> None:
        """Accepte un nouveau client."""
        
        # Le serveur accepte la connexion
        client_socket, _ = self._server_socket.accept()

        # Le serveur ajoute le client a la liste des sockets connectes
        self._client_socs.append(client_socket)

        logger.info(
            f"""
            Le serveur a accepte un nouveau client et l'a 
            ajoute a sa liste de sockets connectes. Le serveur
            compte maintenant {len(self._client_socs)} connectes."""
        )

    def _remove_client(self, client_soc: socket.socket) -> None:
        """Retire le client des structures de données et ferme sa connexion."""

        if client_soc in self._client_socs:
            self._client_socs.remove(client_soc)
        client_soc.close()

        logger.info(
            f"""Un client a quitte. Le serveur a retire le socket associe a
            ce client de sa liste de sockets connectes. Le serveur
            compte maintenant {len(self._client_socs)} connectes."""
        )

    def _create_account(
        self, client_soc: socket.socket, payload: gloutils.AuthPayload
    ) -> gloutils.GloMessage:
        """
        Crée un compte à partir des données du payload.

        Si les identifiants sont valides, créee le dossier de l'utilisateur,
        associe le socket au nouvel l'utilisateur et retourne un succès,
        sinon retourne un message d'erreur.
        """

        username = payload["username"]
        password = payload["password"]

        logger.info(
            f"""Les informations fournis sont:
                - username: {username}
                - password: {password}"""
        )

        # [TODO] VALIDER LES INFORMATIONS DU CLIENT

        logger.info("Le serveur valide les informations du client.")

            # Le serveur s'assure que le nom d'utilisateur ne contient que des caracteres
            # alphanumeriques, _ (underscore), . (point), ou - (trait d'union).
            # [...]

            # Le serveur s'assure que le nom d'utilisateur n'est pas deja pris.
            # *Note : les noms sont insensibles a la casse (BOB == bob)
            # [...]

            # Le serveur s'arrure que le mot de passe est assez securise:
            #   - len(mot_de_passe) >= 10 caracteres
            #   - contient au moins un chiffre
            #   - contient au moins une minuscule
            #   - contient au moins une majuscule
            # [...]

        # [TODO] AJOUTER LES DONNEES DU CLIENT DANS LE SERVEUR

        logger.info("Le serveur ajoute les donnees du client dans le serveur.")

            # Le serveur cree un dossier au nom de l'utilisateur dans le dossier SERVER_DATA_DIR
            # [...]

            # Le serveur hache le mode de passe de l'utilisateur avec l'algorithme `sha3_512`.
            # [...]

            # Le serveur ecrire le mot de passe hache dans un fichier nomme PASSWORD_FILENAME
            # [...]

        username_password_valid = True # supposons que `username` et `password` sont valides

        # Le serveur previent le client du succes avec l'entete OK
        if username_password_valid:
            header = gloutils.Headers.OK
            message = gloutils.GloMessage(header=header)
            data = json.dumps(message)
            glosocket.send_mesg(client_soc, data)

            # Le serveur associe le socket du client à ce nom d’utilisateur
            self._logged_users[client_soc] = payload["username"]

        # Si les identifiants sont invalides ou que le nom d’utilisateur est indisponible,
        # le serveur répond avec l’entete ERROR et un message décrivant le problème
        else:
            header = gloutils.Headers.ERROR
            error_message = "Oops, something went wrong." # [TODO] Ecrire un message d'erreur plus explicatif
            content = gloutils.ErrorPayload(error_message=error_message)
            message = gloutils.GloMessage(header=header,
                                          payload=content)
            data = json.dumps(message)
            glosocket.send_mesg(client_soc, data)

        return message

    def _login(
        self, client_soc: socket.socket, payload: gloutils.AuthPayload
    ) -> gloutils.GloMessage:
        """
        Vérifie que les données fournies correspondent à un compte existant.

        Si les identifiants sont valides, associe le socket à l'utilisateur et
        retourne un succès, sinon retourne un message d'erreur.
        """

        username = payload["username"]
        password = payload["password"]

        logger.info(
            f"""Les informations fournis sont:
                - username: {username}
                - password: {password}"""
        )  

        # [TODO] VALIDER LES INFORMATIONS DU CLIENT

        logger.info("Le serveur valide les informations du client.")

        # Le serveur s’assure que le nom d’utilisateur existe.
        # [...]

        # Le serveur hache le mot de passe et s’assure qu’il correspond à celui stocké dans le
        # dossier de l’utilisateur.
        # [...]

        username_password_valid = True # supposons que `username` et `password` sont valides

        # Le serveur previent le client du succes avec l'entete OK
        if username_password_valid:
            header = gloutils.Headers.OK
            message = gloutils.GloMessage(header=header)
            data = json.dumps(message)
            glosocket.send_mesg(client_soc, data)

            # Le serveur associe le socket du client à ce nom d’utilisateur
            self._logged_users[client_soc] = payload["username"]

        # Si les identifiants sont invalides, le serveur répond avec l’entete ERROR et un message
        # l’accompagnant.
        else:
            header = gloutils.Headers.ERROR
            error_message = "Oops, something went wrong." # [TODO] Ecrire un message d'erreur plus explicatif
            content = gloutils.ErrorPayload(error_message=error_message)
            message = gloutils.GloMessage(header=header,
                                        payload=content)
            data = json.dumps(message)
            glosocket.send_mesg(client_soc, data)

        return message

    def _logout(self, client_soc: socket.socket) -> None:
        """Déconnecte un utilisateur."""

        # Le serveur retire le socket du dictionnaire des utilisateurs connectés
        del self._logged_users[client_soc]

    def _get_email_list(self, client_soc: socket.socket) -> gloutils.GloMessage:
        """
        Récupère la liste des courriels de l'utilisateur associé au socket.
        Les éléments de la liste sont construits à l'aide du gabarit
        SUBJECT_DISPLAY et sont ordonnés du plus récent au plus ancien.

        Une absence de courriel n'est pas une erreur, mais une liste vide.
        """
        # [TODO] Le serveur récupère la liste des courriels depuis le dossier de l’utilisateur.
        logger.info("Le serveur recupere la liste de courriels...")

        # hardcoded email
        payload = gloutils.EmailContentPayload(
            sender="jacob@glo2000.ca",
            destination="alice@glo2000.ca",
            subject="hello world",
            date=gloutils.get_current_utc_time(),
            content="salut ceci est un test.",
        )
        file = json.dumps(payload)
        data = json.loads(file)

        # [TODO] Pour chaque courriel, le serveur récupère l’envoyeur, le sujet et la date.
        sender = data["sender"]
        subject = data["subject"]
        date = data["date"]

        # [TODO] À l’aide du gabarit SUBJECT_DISPLAY, le serveur génère une liste de chaque sujet par
        # ordre chronologique. La numérotation commence à 1 avec le courriel le plus récent.
        email_list = [(sender, subject, date)]
        list_to_send = []
    
        if email_list:
            list_to_send = [] # une liste des sujets des courriels en ordre chronologique (premier element = plus recent)
            for number, email in enumerate(email_list, start=1):
                sender, subject, date = email
                string_to_display = gloutils.SUBJECT_DISPLAY.format(
                    number=number,
                    sender=sender,
                    subject=subject,
                    date=date
                )
                list_to_send.append(string_to_display)
    
        # [TODO] Le serveur transmet la liste au client avec l’entete OK.
        # [TODO] Si l’utilisateur n’a pas de courriel, le serveur transmet une liste vide.
        header = gloutils.Headers.OK
        content = gloutils.EmailListPayload(email_list=list_to_send)
        message = gloutils.GloMessage(header=header,
                                      payload=content)
        data = json.dumps(message)
        glosocket.send_mesg(client_soc, data)

        return message

    def _get_email(
        self, client_soc: socket.socket, payload: gloutils.EmailChoicePayload
    ) -> gloutils.GloMessage:
        """
        Récupère le contenu de l'email dans le dossier de l'utilisateur associé
        au socket.
        """

        choice = payload["choice"]

        # [TODO] Le serveur récupère le courriel associé au choix de l’utilisateur.
        
        logger.info(f"Le serveur recupere le courriel associe au choix #{choice}.")

        # [TODO] Le serveur le transmet au client avec l’entete OK.
        header = gloutils.Headers.OK
        email_infos = gloutils.EmailContentPayload( # temporary hardcoded email payload
            sender="jacob@glo2000.ca",
            destination="alice@glo2000.ca",
            subject="hello world",
            date=gloutils.get_current_utc_time(),
            content="salut ceci est un test."
        )
        message = gloutils.GloMessage(header=header,
                                      payload=email_infos)
        data = json.dumps(message)
        glosocket.send_mesg(client_soc, data)

        return message

    def _get_stats(self, client_soc: socket.socket) -> gloutils.GloMessage:
        """
        Récupère le nombre de courriels et la taille du dossier et des fichiers
        de l'utilisateur associé au socket.
        """

        # [TODO] Le serveur compte le nombre de courriels de l’utilisateur.
        count = 2 # TEMPORARY

        # [TODO] Le serveur calcule le poids total du dossier de l’utilisateur.
        size = 30 # TEMPORARY

        logger.info(f"Le serveur a compte {count} courriels et {size} comme poids total du dossier")

        # [TODO] Le serveur transmet les données au client avec l’entete OK.
        header = gloutils.Headers.OK
        payload = gloutils.StatsPayload(
            count=count,
            size=size
        )
        message = gloutils.GloMessage(header=header,
                                      payload=payload)
        data = json.dumps(message)
        glosocket.send_mesg(client_soc, data)

        return message

    def _send_email(self, payload: gloutils.EmailContentPayload) -> gloutils.GloMessage:
        """
        Détermine si l'envoi est interne ou externe et:
        - Si l'envoi est interne, écris le message tel quel dans le dossier
        du destinataire.
        - Si le destinataire n'existe pas, place le message dans le dossier
        SERVER_LOST_DIR et considère l'envoi comme un échec.
        - Si le destinataire est externe, considère l'envoi comme un échec.

        Retourne un messange indiquant le succès ou l'échec de l'opération.
        """

        logger.info("Le serveur verifie que le destinataire existe avant " \
        "avant d'ecrire le contenu du payload dans le dossier de ce destinataire")

        # [TODO] Le serveur vérifie que le destinataire existe.

        # [TODO] Le serveur utilise les méthodes du module ‘json’ pour écrire le payload tel quel dans
        # le dossier du destinataire.

        # [TODO] Le serveur indique au client le succès de l’opération avec un entete OK.

        sender_username = re.sub(r"@glo2000\.ca$", "", payload["sender"])
        for client_socket, logged_username in self._logged_users.items():
            if sender_username == logged_username:
                client_soc = client_socket

        header = gloutils.Headers.OK
        message = gloutils.GloMessage(header=header)
        data = json.dumps(message)
        glosocket.send_mesg(client_soc, data)

        # [TODO] Si le destinataire n’existe pas, le serveur place le courriel dans le dossier spécial
        # SERVER_LOST_DIR et répond au client avec un entete ERROR et un message d’erreur
        # approprié.

        # [TODO] Si le destinataire est externe, le serveur répond au client avec un entete ERROR et 
        # un message d’erreur approprié.
        header = gloutils.Headers.ERROR
        error_message = "Oops, something went wrong." # [TODO] Ecrire un message d'erreur plus explicatif
        content = gloutils.ErrorPayload(error_message=error_message)
        message = gloutils.GloMessage(header=header,
                                      payload=content)
        data = json.dumps(message)
        glosocket.send_mesg(client_soc, data)

        return message

    def _process_client(self, client_socket: socket.socket) -> None:
        
        try:
            data = glosocket.recv_mesg(client_socket)
            reply = json.loads(data)
        except glosocket.GLOSocketError:
            self._client_socs.remove(client_socket)

        match reply["header"]:

            case gloutils.Headers.AUTH_REGISTER:
                payload = reply["payload"]
                self._create_account(client_socket, payload)

            case gloutils.Headers.AUTH_LOGIN:
                payload = reply["payload"]
                self._create_account(client_socket, payload)

            case gloutils.Headers.BYE:
                self._remove_client(client_socket)

            case gloutils.Headers.INBOX_READING_REQUEST:
                self._get_email_list(client_socket)

            case gloutils.Headers.INBOX_READING_CHOICE:
                payload = reply["payload"]
                self._get_email(client_socket, payload)

            case gloutils.Headers.STATS_REQUEST:
                self._get_stats(client_socket)

            case gloutils.Headers.EMAIL_SENDING:
                payload = reply["payload"]
                self._send_email(payload)

            case gloutils.Headers.AUTH_LOGOUT:
                self._logout(client_socket)

    def run(self):
        """Point d'entrée du serveur."""
        while True:
            waiters = select.select([self._server_socket] + self._client_socs, [], [])[0]
            for waiter in waiters:
                if waiter == self._server_socket:
                    self._accept_client()
                else:
                    self._process_client(waiter)


# NE PAS ÉDITER PASSÉ CE POINT
# NE PAS ÉDITER PASSÉ CE POINT
# NE PAS ÉDITER PASSÉ CE POINT
# NE PAS ÉDITER PASSÉ CE POINT


def _main() -> int:
    server = Server()
    try:
        server.run()
    except KeyboardInterrupt:
        server.cleanup()
    return 0


if __name__ == "__main__":
    sys.exit(_main())
