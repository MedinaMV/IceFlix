#!/usr/bin/env python3

import os
import sys
import json
import secrets
import Ice
import uuid
import datetime
import time
Ice.loadSlice('IceFlix.ice')

try:
    import IceFlix
except ImportError:
    Ice.loadSlice(os.path.join(os.path.dirname(__file__), "IceFlix.ice"))
    import IceFlix

class Authenticator(IceFlix.Authenticator):
    def __init__(self):
        self.id = str(uuid.uuid4())
        with open('users.json', 'r') as fd:
            self.users = json.load(fd)

    def refreshAuthorization(self,user,passwordHash,current=None): # Falta implementar temporizador
        if(self.users.get(user)[0]["passwordHash"] == passwordHash): # Con esto obtenemos la contraseña a partir del usuario
            print("Refreshing...")
            nuevoToken = secrets.token_hex(16)
            self.users.pop(user)
            self.users[user][0]["token"] = nuevoToken
            with open('users.json', 'w') as fd:
                json.dump(self.users,fd)
        else:
            raise IceFlix.Unauthorized
        return nuevoToken

    def isAuthorized(self,userToken,current=None): 
        # Falta implementar que compruebe si está bien con temporizador.
        lista = self.users.values()
        for i in lista:
            if i[0]["token"] == userToken:
                return True
        return False

    def whois(self,userToken,current=None):
        if not self.isAuthorized(userToken):
            raise IceFlix.Unauthorized
        lista = self.users.items()
        for i in lista:
            if i[1][0]["token"] == userToken:
                return i[0]

    def isAdmin(self,adminToken,current=None):  # En principio no tocar
        if not self.isAuthorized(adminToken):
            raise IceFlix.Unauthorized
        return "admin" == self.whois(adminToken)

    def addUser(self,user,passwordHash,adminToken,current=None): 
        if not self.isAdmin(adminToken):
            raise IceFlix.Unauthorized
        self.users[user] = [{"token":secrets.token_hex(16),"passwordHash":passwordHash,"timestamp":time.mktime(datetime.datetime.now().timetuple())}]
        with open('users.json', 'w') as fd:
            json.dump(self.users,fd)

    def removeUser(self,user,adminToken,current=None):  # No tocar
        if not self.isAdmin(adminToken):
            raise IceFlix.Unauthorized
        self.users.pop(user)
        with open('users.json', 'w') as fd:
            json.dump(self.users,fd)

class Server(Ice.Application):
    def run(self, argv):
        broker = self.communicator()
        servant = Authenticator()

        adapter = broker.createObjectAdapterWithEndpoints("AuthenticatorAdapter","tcp")
        prx = adapter.add(servant, broker.stringToIdentity("authenticator"))
        
        adapter.activate()

        print(f'The proxy of Authenticator is "{prx}"')
        
        self.shutdownOnInterrupt()
        broker.waitForShutdown()

        return 0

if __name__ == "__main__":
    server = Server()
    sys.exit(server.main(sys.argv))