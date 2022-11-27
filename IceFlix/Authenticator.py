#!/usr/bin/env python3

import os
import sys
import json
import secrets
import Ice
import uuid
Ice.loadSlice('IceFlix.ice')

try:
    import IceFlix
except ImportError:
    Ice.loadSlice(os.path.join(os.path.dirname(__file__), "IceFlix.ice"))
    import IceFlix

class Authenticator(IceFlix.Authenticator):
    def __init__(self):
        self.id = str(uuid.uuid4())
        # self.prx = ""
        with open('users.json', 'r') as fd:
            self.users = json.load(fd)
        print("Authenticator Created...")

    # def getAuthenticator(self,current=None):
        # return self.prx

    def refreshAuthorization(self,user,passwordHash,current=None): # Falta implementar temporizador
        if(self.users.get(user) == passwordHash): # Con esto obtenemos la contraseña a partir del usuario
            print("Refreshing...")
            nuevoToken = secrets.token_hex(16)
            self.users.pop(user)
            self.users[user] = nuevoToken
            with open('users.json', 'w') as fd:
                json.dump(self.users,fd)
        else:
            raise IceFlix.Unauthorized
        return nuevoToken

    def isAuthorized(self,userToken,current=None): 
        return userToken in self.users.values()

    def whois(self,userToken,current=None): # throws Unauthorized
        if not self.isAuthorized(userToken):
            raise IceFlix.Unauthorized
        lista = self.users.items()
        for clave,valor in lista:
            if valor == userToken:
                return clave

    def isAdmin(self,adminToken,current=None):
        if not self.isAuthorized(adminToken):
            raise IceFlix.Unauthorized
        return "admin" == self.whois(adminToken)

    def addUser(self,user,passwordHash,adminToken,current=None):    # throws Unauthorized, TemporaryUnavailable
        if not self.isAuthorized(adminToken):
            raise IceFlix.Unauthorized
        self.users[user] = passwordHash
        with open('users.json', 'w') as fd:
            json.dump(self.users,fd)

    def removeUser(self,user,adminToken,current=None):  # throws Unauthorized, TemporaryUnavailable
        if not self.isAuthorized(adminToken):
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
        
        # servant.prx = prx
        print(f'The proxy of Authenticator is "{prx}"')
        
        self.shutdownOnInterrupt()
        broker.waitForShutdown()

        return 0

if __name__ == "__main__":
    server = Server()
    sys.exit(server.main(sys.argv))