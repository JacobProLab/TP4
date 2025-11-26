"""\
GLO-2000 Travail pratique 4 - Client 2025
Noms et numéros étudiants:
- Samuel Blanchette
- Wiseley
- Jacob Provencher 111 272 785
"""

import argparse
import getpass
import json
import socket
import sys

import glosocket
import gloutils


class Client:
    """Client pour le serveur mail @glo2000.ca 2025."""

    def __init__(self, destination: str) -> None:
        """
        Prépare et connecte le socket du client `_socket`.

        Prépare un attribut `_username` pour stocker le nom d'utilisateur
        courant. Laissé vide quand l'utilisateur n'est pas connecté.
        """
        self._username = ""
        self._destination = destination

        # Crée un socket et le connecte au serveur.
        self._client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        address = (self._destination, gloutils.APP_PORT)

        try:
            self._client_socket.connect(address)

        # Si la connexion est impossible, le constructeur fait appel à la méthode sys.exit avec un code différent de 0.
        except OSError:
            sys.exit(1)

    def _try_send_message(self, destination_socket: socket.socket, message: str) -> None:
        try:
            glosocket.send_mesg(destination_socket, message)
        except glosocket.GLOSocketError:
            self._client_socket.close()
            sys.exit(1)

    def _register(self) -> None:
        """
        Demande un nom d'utilisateur et un mot de passe et les transmet au
        serveur avec l'entête `AUTH_REGISTER`.

        Si la création du compte s'est effectuée avec succès, l'attribut
        `_username` est mis à jour, sinon l'erreur est affichée.
        """
        # Si l’utilisateur souhaite créer un compte, le client lui demande un
        # nom d’utilisateur avec input et un mot de passe avec getpass.
        username = input("Entrez un nom d'utilisateur: ")
        password = getpass.getpass("Entrez un mot de passe: ")

        # Le client les transmet au serveur avec l’entete AUTH_REGISTER.
        header = gloutils.Headers.AUTH_REGISTER
        payload = gloutils.AuthPayload(username=username,
                                       password=password)
        message = gloutils.GloMessage(header=header,
                                      payload=payload)
        data = json.dumps(message)
        self._try_send_message(self._client_socket, data)

        # Reception de la reponse du serveur
        data = glosocket.recv_mesg(self._client_socket)
        reply = json.loads(data)

        # Si la réponse est OK, l’utilisateur est authentifié.
        if reply["header"] == gloutils.Headers.OK:
            self._username = username

        # Si la réponse est ERROR, le client affiche l’erreur et retourne au menu de connexion.
        elif reply["header"] == gloutils.Headers.ERROR:
            error_message = reply["payload"]["error_message"]
            print(error_message)

    def _login(self) -> None:
        """
        Demande un nom d'utilisateur et un mot de passe et les transmet au
        serveur avec l'entête `AUTH_LOGIN`.

        Si la connexion est effectuée avec succès, l'attribut `_username`
        est mis à jour, sinon l'erreur est affichée.
        """

        username = input("Entrez un nom d'utilisateur: ")
        password = getpass.getpass("Entrez un mot de passe: ")

        # Le client les transmet au serveur avec l’entete AUTH_LOGIN.
        header = gloutils.Headers.AUTH_LOGIN
        payload = gloutils.AuthPayload(username=username,
                                       password=password)
        message = gloutils.GloMessage(header=header,
                                      payload=payload)
        data = json.dumps(message)
        self._try_send_message(self._client_socket, data)

        # Reception de la reponse du serveur
        data = glosocket.recv_mesg(self._client_socket)
        reply = json.loads(data)

        # Si la reponse est OK, l'utilisateur est authentifie
        if reply["header"] == gloutils.Headers.OK:
            self._username = username

        # Si la réponse est ERROR, le client affiche l’erreur et retourne au menu de connexion.
        if reply["header"] == gloutils.Headers.ERROR:
            error_message = reply["payload"]["error_message"]
            print(error_message)

    def _quit(self) -> None:
        """
        Préviens le serveur de la déconnexion avec l'entête `BYE` et ferme le
        socket du client.
        """
        # Si l’utilisateur choisit de quitter, le client prévient le serveur avec l’entete BYE...
        header = gloutils.Headers.BYE
        message = gloutils.GloMessage(header=header)
        data = json.dumps(message)
        self._try_send_message(self._client_socket, data)

        # ...avant de fermer la connexion.
        self._client_socket.close()

    def _read_email(self) -> None:
        """
        Demande au serveur la liste de ses courriels avec l'entête
        `INBOX_READING_REQUEST`.

        Affiche la liste des courriels puis transmet le choix de l'utilisateur
        avec l'entête `INBOX_READING_CHOICE`.

        Affiche le courriel à l'aide du gabarit `EMAIL_DISPLAY`.

        S'il n'y a pas de courriel à lire, l'utilisateur est averti avant de
        retourner au menu principal.
        """

        # Le client demande la liste des courriels avec l’entete INBOX_READING_REQUEST.
        header = gloutils.Headers.INBOX_READING_REQUEST
        message = gloutils.GloMessage(header=header)
        data = json.dumps(message)
        self._try_send_message(self._client_socket, data)

        # Reception de la reponse du serveur
        data = glosocket.recv_mesg(self._client_socket)
        reply = json.loads(data)
        email_list = reply["payload"]["email_list"]

        # Si la liste contient au moins un courriel, elle est affichée, sinon le client retourne au
        # menu principal.
        if email_list:
            for email in email_list:
                print(email)

            # L’utilisateur choisit un courriel dans la liste.
            choice = int(input(f"Entrez votre choix [1-{len(email_list)}]: "))

            # Le client transmet ce choix avec l’entete INBOX_READING_CHOICE.
            header = gloutils.Headers.INBOX_READING_CHOICE
            payload = gloutils.EmailChoicePayload(choice=choice)
            message = gloutils.GloMessage(header=header,
                                        payload=payload)
            data = json.dumps(message)
            self._try_send_message(self._client_socket, data)

            # Reception de la reponse du serveur
            data = glosocket.recv_mesg(self._client_socket)
            reply = json.loads(data)
            email_content = reply["payload"]

            # Le client affiche le courriel à l’aide du gabarit EMAIL_DISPLAY et retourne au menu
            # principal.
            string_to_display = gloutils.EMAIL_DISPLAY.format(
                sender=email_content["sender"],
                to=email_content["destination"],
                subject=email_content["subject"],
                date=email_content["date"],
                body=email_content["content"],
            )
            print(string_to_display)
        
        # s'il n'y pas de courriel, on averti l'utilisateur
        else:
            print("Vous n'avez aucun courriel.")

    def _send_email(self) -> None:
        """
        Demande à l'utilisateur respectivement:
        - l'adresse email du destinataire,
        - le sujet du message,
        - le corps du message.

        La saisie du corps se termine par un point seul sur une ligne.

        Transmet ces informations avec l'entête `EMAIL_SENDING`.
        """
        # Variables
        sender = f"{self._username}@{gloutils.SERVER_DOMAIN}"

        # Le client demande à l’utilisateur respectivement : dest, subject, body
        destination = input("Entrez l'adresse du destinataire: ")
        subject = input("Entrez le sujet: ")
        print("Entrez le contenu du courriel, terminez la saisie avec un '.'seul sur une ligne:")
        body = ""
        buffer = ""
        while (buffer != ".\n"):
            body += buffer
            buffer = input() + '\n'

        # Le client récupère l’heure courante depuis le module ‘gloutils’.
        current_date_time = gloutils.get_current_utc_time()

        # Le client transfère les informations avec un entete EMAIL_SENDING.
        header = gloutils.Headers.EMAIL_SENDING
        payload = gloutils.EmailContentPayload(
            sender=sender,
            destination=destination,
            subject=subject,
            date=current_date_time,
            content=body
        )
        message = gloutils.GloMessage(header=header,
                                      payload=payload)
        data = json.dumps(message)
        self._try_send_message(self._client_socket, data)

        # Reception de la reponse du serveur
        data = glosocket.recv_mesg(self._client_socket)
        reply = json.loads(data)

        # Le client affiche si l’envoi s’est effectué avec succès.
        if reply["header"] == gloutils.Headers.OK:
            print(f"Votre courriel a bel et bien été envoyé à {destination} !")

        elif reply["header"] == gloutils.Headers.ERROR:
            print(reply["payload"]["error_message"])

    def _check_stats(self) -> None:
        """
        Demande les statistiques au serveur avec l'entête `STATS_REQUEST`.

        Affiche les statistiques à l'aide du gabarit `STATS_DISPLAY`.
        """
        # Le client demande les statistiques du compte avec un entete STATS_REQUEST.
        header = gloutils.Headers.STATS_REQUEST
        message = gloutils.GloMessage(header=header)
        data = json.dumps(message)
        self._try_send_message(self._client_socket, data)

        # Reception de la reponse du serveur
        data = glosocket.recv_mesg(self._client_socket)
        reply = json.loads(data)

        # Le client affiche les statistiques en utilisant le gabarit STATS_DISPLAY.
        string_to_display = gloutils.STATS_DISPLAY.format(**reply["payload"])
        print(string_to_display)

    def _logout(self) -> None:
        """
        Préviens le serveur avec l'entête `AUTH_LOGOUT`.

        Met à jour l'attribut `_username`.
        """

        # Le client informe le serveur de la déconnexion avec l’entete AUTH_LOGOUT.
        header = gloutils.Headers.AUTH_LOGOUT
        message = gloutils.GloMessage(header=header)
        data = json.dumps(message)
        self._try_send_message(self._client_socket, data)

        # Le client retourne sur le menu de connexion.
        self._username = ""

    def run(self) -> None:
        """Point d'entrée du client."""

        should_quit = False
        while not should_quit:
            if not self._username:
                print(gloutils.CLIENT_AUTH_CHOICE)

                # S'assurer que l'entree est valide
                if (user_input := input("Entrez votre choix [1-3]: ")) not in ["1", "2", "3"]:
                    print(f"Aucune option correspond à {user_input}. Réessayez.")
                    continue

                match int(user_input):
                    case 1:
                        self._register()
                    case 2:
                      self._login()
                    case 3:
                        self._quit()
                        should_quit = True
            else:
                print(gloutils.CLIENT_USE_CHOICES)

                # S'assurer que l'entree est valide
                if (user_input := input("Entrez votre choix [1-4]: ")) not in ["1", "2", "3", "4"]:
                    print(f"Aucune option correspond à {user_input}. Réessayez.")
                    continue

                match int(user_input):
                    case 1:
                        self._read_email()
                    case 2:
                        self._send_email()
                    case 3:
                        self._check_stats()
                    case 4:
                        self._logout()


# NE PAS ÉDITER PASSÉ CE POINT
# NE PAS ÉDITER PASSÉ CE POINT
# NE PAS ÉDITER PASSÉ CE POINT
# NE PAS ÉDITER PASSÉ CE POINT


def _main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-d",
        "--destination",
        action="store",
        dest="dest",
        required=True,
        help="Adresse IP/URL du serveur.",
    )
    args = parser.parse_args(sys.argv[1:])
    client = Client(args.dest)
    client.run()
    return 0


if __name__ == "__main__":
    sys.exit(_main())
