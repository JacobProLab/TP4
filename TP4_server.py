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

from datetime import datetime
from pathlib import Path

import glosocket
import gloutils


logging.basicConfig(
    format='%(asctime)s %(levelname)s: %(message)s',
    level=logging.DEBUG
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

        # S'assurer que le dossier SERVER_DATA_DIR existe et
        # et qu'il contient le SERVER_LOST_DIR. Les creer sinon.
        self._server_data_dir_path = Path(gloutils.SERVER_DATA_DIR)
        self._server_lost_dir_path = gloutils.SERVER_LOST_DIR
        fullpath = self._server_data_dir_path / self._server_lost_dir_path
        fullpath.mkdir(parents=True, exist_ok=True)

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
            f"""Les informations fournis s  ont:
                - username: {username}
                - password: {password}"""
        )

        # VALIDER LES INFORMATIONS DU CLIENT

        logger.info("Le serveur valide les informations du client.")

        # Le serveur s'assure que le nom d'utilisateur ne contient que des caracteres
        # alphanumeriques, _ (underscore), . (point), ou - (trait d'union).
        is_valid_username_syntax = bool(re.fullmatch(r"[a-zA-Z0-9_.-]+", username))

        # Le serveur s'assure que le nom d'utilisateur n'est pas deja pris et qu'il
        # n'est pas `gloutils.SERVER_LOST_DIR` *Note : les noms sont insensibles a la casse (BOB == bob)
        is_not_taken_username = True
        for repo in self._server_data_dir_path.iterdir():
            if username.lower() in [repo.name.lower(), self._server_lost_dir_path.lower()]:
                is_not_taken_username = False
                break

        is_valid_username = is_valid_username_syntax and is_not_taken_username

        # Le serveur s'assure que le mot de passe est assez securise:
        #   - len(mot_de_passe) >= 10 caracteres
        #   - contient au moins un chiffre
        #   - contient au moins une minuscule
        #   - contient au moins une majuscule

        is_long_enough_password = bool(len(password) >= 10)

        at_least_one_digit = r"(?=.*\d)"
        at_least_lower_case = r"(?=.*[a-z])"
        at_least_upper_case = r"(?=.*[A-Z])"
        string_pattern = "^{}{}{}.+$".format(at_least_one_digit,
                                             at_least_lower_case,
                                             at_least_upper_case)
        pattern = re.compile(string_pattern)
        is_password_complex_enough = bool(re.match(pattern, password))

        is_secure_password = is_long_enough_password and is_password_complex_enough

        # Si user infos sont valides --> ajouter les donnees du client dans dossier de donnees du serveur
        if is_valid_username and is_secure_password:
            logger.info("Le serveur ajoute les donnees du client dans le serveur.")

            # Le serveur cree un dossier au nom de l'utilisateur dans le dossier SERVER_DATA_DIR
            user_mail_dir_path = self._server_data_dir_path / username / "emails"
            user_mail_dir_path.mkdir(parents=True)

            # Le serveur hache le mode de passe de l'utilisateur avec l'algorithme `sha3_512`.
            hash_password = hashlib.sha3_512(password.encode('utf_8')).hexdigest()

            # Le serveur ecrit le mot de passe hache dans un fichier nomme PASSWORD_FILENAME
            user_dir_path = self._server_data_dir_path / username / f"{gloutils.PASSWORD_FILENAME}.json"
            with open(user_dir_path, "w", encoding='utf-8') as file:
                content = {"password": hash_password}
                json.dump(content, file, indent=4)

            # Le serveur previent le client du succes avec l'entete OK
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

            username_syntax_message = " - Le nom d'utilisateur est invalide." if not is_valid_username_syntax else ""
            username_taken_message = " - Ce nom d'utilisateur est déjà utilisé." if not is_not_taken_username else ""
            password_security_message = " - Le mot de passe n'est pas assez sûr." if not is_secure_password else ""
            messages = [username_syntax_message, username_taken_message, password_security_message]

            error_message = "La création a échoué:\n" + "\n".join([message for message in messages if message])

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

        # VALIDER LES INFORMATIONS DU CLIENT
        logger.info("Le serveur valide les informations du client.")

        is_username_exists = False
        is_valid_password = False

        # Le serveur s’assure que le nom d’utilisateur existe.
        for repo in self._server_data_dir_path.iterdir():
            if repo.name == self._server_lost_dir_path:
                continue
            elif username.lower() == repo.name.lower():
                is_username_exists = True
                break

        # Le serveur hache le mot de passe et s’assure qu’il correspond à celui stocké dans le
        # dossier de l’utilisateur.
        if is_username_exists:
            password_file_path = self._server_data_dir_path / username / f"{gloutils.PASSWORD_FILENAME}.json"

            with open(password_file_path, "r", encoding='utf-8') as file:
                stored_hash = json.load(file)["password"]
            provided_hash = hashlib.sha3_512(password.encode('utf-8')).hexdigest()
            
            is_valid_password = hmac.compare_digest(provided_hash, stored_hash)

        # Le serveur previent le client du succes avec l'entete OK
        if is_valid_password:
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

            username_exists_message = " - Ce nom d'utilisateur n'existe pas." if not is_username_exists else ""
            password_security_message = " - Le mot de passe est incorrecte." if not is_valid_password else ""
            messages = [username_exists_message, password_security_message]
            error_message = "La création a échoué:\n" + "\n".join([message for message in messages if message])

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
        # Le serveur récupère la liste des courriels depuis le dossier de l’utilisateur.
        logger.info("Le serveur recupere la liste de courriels...")

        client_username = self._logged_users[client_soc]
        dir_path = self._server_data_dir_path / client_username / "emails"

        email_list = []
        for email in dir_path.iterdir():
            with open(email, "r", encoding='utf-8') as file:
                email_content_payload = json.load(file)
                email_list.append(
                    (email_content_payload["sender"],
                     email_content_payload["subject"],
                     email_content_payload["date"])
                )

        list_to_send = []
    
        if email_list:
            for index, email in enumerate(sorted(email_list,
                                                key=lambda time:
                                                datetime.strptime(time[-1], "%a, %d %b %Y %H:%M:%S %z"),
                                                reverse=True),
                                                start=1):
                sender, subject, date = email
                string_to_display = gloutils.SUBJECT_DISPLAY.format(
                    number=index,
                    sender=sender,
                    subject=subject,
                    date=date
                )
                list_to_send.append(string_to_display)
    
        # Le serveur transmet la liste au client avec l’entete OK.
        # Si l’utilisateur n’a pas de courriel, le serveur transmet une liste vide.
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
        client_username = self._logged_users[client_soc]
        dir_path = self._server_data_dir_path / client_username / "emails"

        emails = []
        for email in dir_path.iterdir():
            with open(email, "r", encoding='utf-8') as file:
                email_content_payload = json.load(file)
                emails.append((email_content_payload, email_content_payload["date"]))

        for index, email_payload in enumerate(sorted(emails,
                                                      key=lambda time:
                                                      datetime.strptime(time[-1], "%a, %d %b %Y %H:%M:%S %z"),
                                                      reverse=True),
                                                      start=1):
            if index == choice:
                email_infos = gloutils.EmailContentPayload(**email_payload[0])
        
        logger.info(f"Le serveur recupere le courriel associe au choix #{choice}.")

        # [TODO] Le serveur le transmet au client avec l’entete OK.
        header = gloutils.Headers.OK
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

        user_dir_path = self._server_data_dir_path / self._logged_users[client_soc] / "emails"

        # Le serveur compte le nombre de courriels de l’utilisateur.
        count = sum(1 for file in user_dir_path.iterdir() if file.is_file())

        # Le serveur calcule le poids total du dossier de l’utilisateur.
        size = sum(file.stat().st_size for file in user_dir_path.iterdir() if file.is_file()) # [TODO] need to ask if we include password file

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
    
    def _parse_email_address(self, email_address):
        """
        :return: tuple[username, domain]
        """
        return re.sub(r"@glo2000\.ca$", "", email_address)

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

        # Variables
        receiver = self._parse_email_address(payload["destination"]) # !!! TEMPORARY WAY OF PARSING USERNAME...
        is_receiver_exists = False
        is_external_receiver = False # [TODO]

        # Le serveur vérifie que le destinataire existe.
        for repo in self._server_data_dir_path.iterdir():
            if repo.name == self._server_lost_dir_path:
                continue
            elif receiver.lower() == repo.name.lower():
                is_receiver_exists = True
                break
        
        # Prep email_id using (sender and sent datetime)
        sender = self._parse_email_address(payload["sender"])
        date = payload["date"]
        email_id = hashlib.sha256(f"{sender}_{date}".encode('utf-8')).hexdigest()
        filename = f"{email_id}.json"

        # Get client_socket by matching sender with logged_users
        for client_socket, logged_username in self._logged_users.items():
            if sender == logged_username:
                client_soc = client_socket

        # Le serveur utilise les méthodes du module ‘json’ pour écrire le payload tel quel dans le dossier du destinataire.
        if is_receiver_exists and not is_external_receiver:

            dest_file = self._server_data_dir_path / receiver / "emails" / filename

            # Le serveur indique au client le succès de l’opération avec un entete OK.
            header = gloutils.Headers.OK
            message = gloutils.GloMessage(header=header)
            data = json.dumps(message)
            glosocket.send_mesg(client_soc, data)

            # Placer le courriel dans `dest_file`
            with open(dest_file, "w", encoding="utf-8") as file:
                json.dump(payload, file, indent=4)

        # Si le destinataire n’existe pas, le serveur place le courriel dans le dossier spécial
        # SERVER_LOST_DIR et répond au client avec un entete ERROR et un message d’erreur approprié.
        elif not is_receiver_exists:
            
            error_message = "Ce système ne fait pas l'envoi de courriel à l'externe."

            if not is_external_receiver:
                dest_file = self._server_data_dir_path / self._server_lost_dir_path / filename
                error_message = "Nous n'avons pas pu trouvé l'utilisateur a qui vous souhaitez enovoyé un courriel."

                # Placer le courriel dans `dest_file`
                with open(dest_file, "w", encoding="utf-8") as file:
                    json.dump(payload, file, indent=4)

            # Si le destinataire est externe, le serveur répond au client avec un entete ERROR et 
            # un message d’erreur approprié.
            header = gloutils.Headers.ERROR
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
                self._login(client_socket, payload)

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
