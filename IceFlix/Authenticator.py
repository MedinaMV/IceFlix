#!/usr/bin/env python3

import os
import sys
import json
import secrets
import Ice
import uuid
import datetime
import time
Ice.loadSlice('IceFlix/IceFlix.ice')

try:
    import IceFlix
except:
    Ice.loadSlice(os.path.join(os.path.dirname(__file__), "IceFlix/IceFlix.ice"))
    import IceFlix

class Authenticator(IceFlix.Authenticator):
    def __init__(self,adminToken):
        self.id = str(uuid.uuid4())
        self.adminToken = adminToken
        with open('IceFlix/users.json', 'r') as fd:
            self.users = json.load(fd)

    def refreshAuthorization(self,user,passwordHash,current=None): # Falta implementar temporizador
        if(self.users.get(user)[0]["passwordHash"] == passwordHash): 
            nuevoToken = secrets.token_hex(16)
            self.users.pop(user)
            self.users[user][0]["token"] = nuevoToken
            with open('IceFlix/IceFlix/users.json', 'w') as fd:
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
        # Si no es un token autorizado se lanza la excepcion.
        if not self.isAuthorized(userToken):
            raise IceFlix.Unauthorized

        # Buscamos dentro de los valores de nuestro diccionario y devolvemos la clave.
        lista = self.users.items()
        for i in lista:
            if i[1][0]["token"] == userToken:
                return i[0]

    def isAdmin(self,adminToken,current=None):  
        # Si el token no es del admin se lanza la excepcion.
        if self.adminToken == adminToken:
            return True
        return False

    def addUser(self,user,passwordHash,adminToken,current=None): 
        # Si el token suministrado no es el del admin, se lanza la excepcion.
        if not self.isAdmin(adminToken):
            raise IceFlix.Unauthorized

        # No se permiten usuarios con el mismo nombre por lo tanto, si ya existe uno, se lanza la excepcion.
        if self.users.get(user):
            raise IceFlix.Unauthorized

        # Guardamos el nuevo usuario y de forma persistente también.
        self.users[user] = [{"token":secrets.token_hex(16),"passwordHash":passwordHash,"timestamp":time.mktime(datetime.datetime.now().timetuple())}]
        with open('IceFlix/users.json', 'w') as fd:
            json.dump(self.users,fd)

    def removeUser(self,user,adminToken,current=None):
        # Si el token suministrado no es el del admin, se lanza la excepcion.
        if not self.isAdmin(adminToken):
            raise IceFlix.Unauthorized
        
        # Si el usuario no existe, no se puede borrar.
        if not self.users.get(user):
            raise IceFlix.Unauthorized

        # Borramos al usuario de nuestra estructura de datos y del archivo json.
        self.users.pop(user)
        with open('IceFlix/users.json', 'w') as fd:
            json.dump(self.users,fd)

class Server(Ice.Application):
    def run(self, argv):
        broker = self.communicator()
        adminToken = self.communicator().getProperties().getProperty('AdminToken')
        servant = Authenticator(adminToken)

        adapter = broker.createObjectAdapterWithEndpoints("AuthenticatorAdapter","tcp")
        prx = adapter.add(servant, broker.stringToIdentity("authenticator"))
        
        adapter.activate()

        print(f'The proxy of Authenticator is "{prx}"')

        main = self.communicator().getProperties().getProperty('ProxyMain')
        prxMain = IceFlix.MainPrx.uncheckedCast((self.communicator().stringToProxy(main)))

        # try:
            # prxMain.newService(prx,servant.id)
            # print("Servicio anunciado correctamente!")
        # except Ice.ConnectionRefusedException:
            # print("El servicio Main no se encuentra disponible...")
            # self.communicator().shutdown()
        
        self.shutdownOnInterrupt()
        broker.waitForShutdown()

        return 0

if __name__ == "__main__":
    server = Server()
    sys.exit(server.main(sys.argv))