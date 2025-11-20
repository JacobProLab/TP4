"""\
GLO-2000 Travail pratique 4 - Client 2025
Noms et numéros étudiants:
-
-
-
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

        # Si la connexion est impossible, le constructeur fait appel à la méthode sys.exit avec
        # un code différent de 0.
        except OSError:
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

        # Le client les transmet au serveur avec l’entete AUTH_ appropriée.
        header = gloutils.Headers.AUTH_REGISTER
        payload = gloutils.AuthPayload(username=username,
                                       password=password)
        message = gloutils.GloMessage(header=header,
                                      payload=payload)
        data = json.dumps(message)
        glosocket.send_mesg(self._client_socket, data)

        # Reception de la reponse du serveur
        data = glosocket.recv_mesg(self._client_socket)
        reply = json.loads(data)

        # Si la réponse est OK, l’utilisateur est authentifié.
        if reply["header"] == gloutils.Headers.OK:
            self._username = username
            print(f"Bravo, le nom {username} est un nom valider par le serveur!") # temporary

        # [TODO] Si la réponse est ERROR, le client affiche l’erreur et retourne au menu de connexion.

    def _login(self) -> None:
        """
        Demande un nom d'utilisateur et un mot de passe et les transmet au
        serveur avec l'entête `AUTH_LOGIN`.

        Si la connexion est effectuée avec succès, l'attribut `_username`
        est mis à jour, sinon l'erreur est affichée.
        """

    def _quit(self) -> None:
        """
        Préviens le serveur de la déconnexion avec l'entête `BYE` et ferme le
        socket du client.
        """
        # Si l’utilisateur choisit de quitter, le client prévient le serveur avec l’entete BYE...
        header = gloutils.Headers.BYE
        message = gloutils.GloMessage(header=header)
        data = json.dumps(message)
        glosocket.send_mesg(self._client_socket, data)

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

        # [TODO] Le client demande la liste des courriels avec l’entete INBOX_READING_REQUEST.

        # [TODO] Si la liste contient au moins un courriel, elle est affichée, sinon le client retourne au
        # menu principal.

        # [TODO] L’utilisateur choisit un courriel dans la liste.

        # [TODO] Le client transmet ce choix avec l’entete INBOX_READING_CHOICES.

        # [TODO] Le client affiche le courriel à l’aide du gabarit EMAIL_DISPLAY et retourne au menu
        # principal.

    def _send_email(self) -> None:
        """
        Demande à l'utilisateur respectivement:
        - l'adresse email du destinataire,
        - le sujet du message,
        - le corps du message.

        La saisie du corps se termine par un point seul sur une ligne.

        Transmet ces informations avec l'entête `EMAIL_SENDING`.
        """

        # [TODO] Le client demande à l’utilisateur respectivement :
        #   - L’adresse de destination
        #   - Le sujet du courriel
        #   - Le contenu du courriel

        # [TODO] Le client récupère l’heure courante depuis le module ‘gloutils’.

        # [TODO] Le client transfère les informations avec un entete EMAIL_SENDING.

        # [TODO] Le client affiche si l’envoi s’est effectué avec succès.

    def _check_stats(self) -> None:
        """
        Demande les statistiques au serveur avec l'entête `STATS_REQUEST`.

        Affiche les statistiques à l'aide du gabarit `STATS_DISPLAY`.
        """
        # [TODO] Le client demande les statistiques du compte avec un entete STATS_REQUEST.

        # [TODO] Le client affiche les statistiques en utilisant le gabarit STATS_DISPLAY.

    def _logout(self) -> None:
        """
        Préviens le serveur avec l'entête `AUTH_LOGOUT`.

        Met à jour l'attribut `_username`.
        """

        # [TODO] Le client informe le serveur de la déconnexion avec l’entete AUTH_LOGOUT.

        # [TODO] Le client retourne sur le menu de connexion.

    def run(self) -> None:
        """Point d'entrée du client."""

        should_quit = False
        while not should_quit:
            if not self._username:

                # Le client affiche le menu de connexion à l’utilisateur.
                print(gloutils.CLIENT_AUTH_CHOICE)

                match int(input("Entrez votre choix [1-3]: ")):
                    case 1:
                        self._register()
                    # case 2:
                    #   self._login()
                    case 3:
                        self._quit()
                        should_quit = True
            else:
                print(gloutils.CLIENT_USE_CHOICES)
                break


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
