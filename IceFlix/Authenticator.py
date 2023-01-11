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
import topics
Ice.loadSlice('IceFlix/IceFlix.ice')

PATH_USERS = 'IceFlix/users.json'

try:
    import IceFlix
except ModuleNotFoundError:
    Ice.loadSlice(os.path.join(os.path.dirname(__file__), "IceFlix/IceFlix.ice"))
    import IceFlix

class Authenticator(IceFlix.Authenticator):
    def __init__(self,adminToken):
        self.id = str(uuid.uuid4())
        self.adminToken = adminToken
        self.proxies = []
        self.userUpdate = None
        try:
            with open(PATH_USERS,'r') as fd:
                self.users = json.load(fd)
        except:
            self.users = {}

    def refreshAuthorization(self,user,passwordHash,current=None):
        # Si el usuario no está dado de alta, lanzamos excepción.
        if not self.users.get(user):
            raise IceFlix.Unauthorized

        # Comprobamos que la contraseña conincida con la del usuario.
        if(self.users.get(user)[0]["passwordHash"] == passwordHash): 

            #Para revocar el token borramos al usuario y volvemos a generar un token para el mismo.
            self.users.pop(user)
            nuevoToken = secrets.token_hex(16)

            # Volvemos a dar de alta al usuario 
            self.users[user] = [{"token":nuevoToken,"passwordHash":passwordHash,
            "timestamp":time.mktime(datetime.datetime.now().timetuple())}]

            # Y lo guardamos de forma persistente.
            with open(PATH_USERS,'w') as fd:
                json.dump(self.users,fd)

        self.userUpdate.newToken(user,nuevoToken,self.id)
        return nuevoToken

    def isAuthorized(self,userToken,current=None):
        # Obtenemos los valores del diccionario. 
        lista = self.users.values()

        # Buscamos si el token pasado por parámetro coincide con alguno de los de nuestros usuarios.
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
        self.users[user] = [{"token":secrets.token_hex(16),"passwordHash":passwordHash,
        "timestamp":time.mktime(datetime.datetime.now().timetuple())}]

        with open(PATH_USERS,'w') as fd:
            json.dump(self.users,fd)
        
        self.userUpdate.newUser(user,passwordHash,self.id)

    def removeUser(self,user,adminToken,current=None):
        # Si el token suministrado no es el del admin, se lanza la excepcion.
        if not self.isAdmin(adminToken):
            raise IceFlix.Unauthorized
        
        # Si el usuario no existe, no se puede borrar.
        if not self.users.get(user):
            raise IceFlix.Unauthorized

        # Borramos al usuario de nuestra estructura de datos y del archivo json.
        self.users.pop(user)
        with open(PATH_USERS,'w') as fd:
            json.dump(self.users,fd)

        self.userUpdate.removeUser(user,self.id)
    
    def bulkUpdate(self,current=None):
        currentUsers = {}
        activeTokens = {}

        for i in self.users.keys():
            if self.users.get(i)[0]["token"] != "":
                activeTokens[i] = self.users.get(i)[0]["token"]
                currentUsers[i] = self.users.get(i)[0]["passwordHash"]

        auth_data = IceFlix.AuthenticatorData()

        auth_data.adminToken = self.adminToken
        auth_data.currentUsers = currentUsers
        auth_data.activeTokens = activeTokens

        return auth_data

class UserUpdate(IceFlix.UserUpdate):
    def __init__(self,auth:Authenticator):
        self.auth = auth

    def newToken(self,user,token,serviceId,current=None):
        if(serviceId in self.auth.proxies and serviceId != self.auth.id):
            self.auth.users.get(user)[0]["token"] = token
            with open(PATH_USERS,'w') as fd:
                json.dump(self.auth.users,fd)

    def revokeToken(self,token,serviceId,current=None):
        if(serviceId in self.auth.proxies and serviceId != self.auth.id):
            user = self.auth.whois(token)
            self.auth.users.get(user)[0]["token"] = ""
            with open(PATH_USERS,'w') as fd:
                json.dump(self.auth.users,fd)

    def newUser(self,user,passwordHash,serviceId,current=None):
        if(serviceId in self.auth.proxies and serviceId != self.auth.id):
            self.auth.users[user] = [{"token":secrets.token_hex(16),"passwordHash":passwordHash,
            "timestamp":time.mktime(datetime.datetime.now().timetuple())}]
            with open(PATH_USERS,'w') as fd:
                json.dump(self.auth.users,fd)

    def removeUser(self,user,serviceId,current=None):
        if(serviceId in self.auth.proxies and serviceId != self.auth.id):
            self.auth.users.pop(user)
            with open(PATH_USERS,'w') as fd:
                json.dump(self.auth.users,fd)

class Announcement(IceFlix.Announcement):
    def __init__(self,auth:Authenticator):
        self.auth = auth

    def announce(self,service,serviceId):
        print("Hello World")

class Server(Ice.Application):
    def run(self, argv):
        broker = self.communicator()
        adminToken = self.communicator().getProperties().getProperty('AdminToken')
        servant = Authenticator(adminToken)

        adapter = broker.createObjectAdapterWithEndpoints("AuthenticatorAdapter","tcp")
        prx = adapter.add(servant,broker.stringToIdentity("authenticator"))
        print(f'Auth proxy is "{prx}"')

        adapter.activate()

        """try:
            # Iniciamos el hilo que anuncia el servicio cada 30s.
            hilo1 = threading.Thread(target=self.anunciarServicio,args=(prxMain,servant.id,prx,))
            hilo1.start()

            # Iniciamos el hilo (que se ejecuta cada 30s) que revoca los tokens con un tiempo de vida de 2mins o superior.
            hilo2 = threading.Thread(target=self.revocarToken,args=(servant,))
            hilo2.start()
        except Ice.ConnectionRefusedException:
            print("El servicio Main no se encuentra disponible...")
            self.communicator().shutdown()
        except KeyboardInterrupt:
            hilo1.kill()
            hilo2.kill()
            self.communicator().shutdown()"""

        servant_updates = UserUpdate(servant)
        proxy_updates = adapter.addWithUUID(servant_updates)
        topic_updates = topics.getTopic(topics.getTopicManager(broker),'UserUpdates')
        topic_updates.subscribeAndGetPublisher({}, proxy_updates)
        publisher_updates = topics.getTopic(topics.getTopicManager(broker), 'UserUpdates').getPublisher()
        servant.userUpdate = IceFlix.UserUpdatePrx.uncheckedCast(publisher_updates)

        self.shutdownOnInterrupt()
        broker.waitForShutdown()

        return 0
        
    def anunciarServicio(self,prxmain,servantID,authprx):
        while True:
            # Esperamos 30s para realizar un announce.
            time.sleep(30)
            try:
                prxmain.announce(authprx,servantID)
            except Ice.ConnectionRefusedException:
                print("El servicio main no se encuentra disponible... ")
                break

    def revocarToken(self,auth:Authenticator):
        while True:
            for i in auth.users:
                if (time.mktime(datetime.datetime.now().timetuple()) - auth.users.get(i)[0]["timestamp"]) >= 120:
                    auth.userUpdate.revokeToken(auth.users.get(i)[0]["token"],auth.id)
                    auth.users.get(i)[0]["token"] = ""
            with open(PATH_USERS,'w') as fd:
                json.dump(auth.users,fd)
            # Cada 30s se comprueba el timestamp de los tokens de usuario.
            time.sleep(30)
            
if __name__ == "__main__":
    server = Server()
    sys.exit(server.main(sys.argv))
