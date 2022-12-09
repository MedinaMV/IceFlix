#!/usr/bin/env python3

import os
import sys
import json
import threading
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
        try:
            with open('IceFlix/users.json','r') as fd:
                self.users = json.load(fd)
        except:
            self.users = {}

    def refreshAuthorization(self,user,passwordHash,current=None):
        if not self.users.get(user):
            raise IceFlix.Unauthorized

        if(self.users.get(user)[0]["passwordHash"] == passwordHash): 
            self.users.pop(user)
            nuevoToken = secrets.token_hex(16)
            self.users[user] = [{"token":nuevoToken,"passwordHash":passwordHash,"timestamp":time.mktime(datetime.datetime.now().timetuple())}]
            with open('IceFlix/users.json','w') as fd:
                json.dump(self.users,fd)
        return nuevoToken

    def isAuthorized(self,userToken,current=None):
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
        with open('IceFlix/users.json','w') as fd:
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
        with open('IceFlix/users.json','w') as fd:
            json.dump(self.users,fd)

class Server(Ice.Application):
    def run(self, argv):
        broker = self.communicator()
        adminToken = self.communicator().getProperties().getProperty('AdminToken')
        servant = Authenticator(adminToken)

        adapter = broker.createObjectAdapterWithEndpoints("AuthenticatorAdapter","tcp")
        prx = adapter.add(servant,broker.stringToIdentity("authenticator"))
        
        adapter.activate()

        print(f'The proxy of Authenticator is "{prx}"')

        main = self.communicator().getProperties().getProperty('ProxyMain')
        prxMain = IceFlix.MainPrx.uncheckedCast((self.communicator().stringToProxy(main)))

        try:
            prxMain.newService(prx,servant.id)
            hilo1 = threading.Thread(target=self.anunciarServicio,args=(prxMain,servant.id,prx,))
            hilo1.start()

            hilo2 = threading.Thread(target=self.revocarToken,args=(servant,))
            hilo2.start()
        except Ice.ConnectionRefusedException:
            print("El servicio Main no se encuentra disponible...")
            self.communicator().shutdown()

        
        self.shutdownOnInterrupt()
        broker.waitForShutdown()

        return 0
        
    def anunciarServicio(self,prxmain,servantID,authprx):
        while True:
            time.sleep(30)
            try:
                prxmain.announce(authprx,servantID)
            except Ice.ConnectionRefusedException:
                print("El servicio main no se encuentra disponible... ")

    def revocarToken(self,auth:Authenticator):
        while True:
            for i in auth.users:
                if (time.mktime(datetime.datetime.now().timetuple()) - auth.users.get(i)[0]["timestamp"]) > 120:
                    auth.users.get(i)[0]["token"] = ""
            with open('IceFlix/users.json','w') as fd:
                json.dump(auth.users,fd)
            time.sleep(30)
            

if __name__ == "__main__":
    server = Server()
    sys.exit(server.main(sys.argv))