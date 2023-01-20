#!/usr/bin/env python3

import os
import sys
import json
import threading
import secrets
import Ice
import IceStorm
import uuid
import datetime
import time
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
        self.proxies = {}
        self.userUpdate = None
        self.announcement = None
        try:
            with open(PATH_USERS,'r') as fd:
                self.users = json.load(fd)
        except:
            self.users = {}

    def refreshAuthorization(self,user,passwordHash,current=None):
        """Si el usuario no está dado de alta, lanzamos excepción."""
        if not self.users.get(user):
            raise IceFlix.Unauthorized

        """Comprobamos que la contraseña conincida con la del usuario."""
        if(self.users.get(user)[0]["passwordHash"] == passwordHash): 

            """Creamos el nuevo token"""
            nuevoToken = secrets.token_hex(16)

            """Volvemos a dar de alta al usuario """
            self.users[user] = [{"token":nuevoToken,"passwordHash":passwordHash,
            "timestamp":time.mktime(datetime.datetime.now().timetuple())}]

            """ Y lo guardamos de forma persistente."""
            with open(PATH_USERS,'w') as fd:
                json.dump(self.users,fd)

        self.userUpdate.newToken(user,nuevoToken,self.id)
        return nuevoToken

    def isAuthorized(self,userToken,current=None):
        """Obtenemos los valores del diccionario. """
        lista = self.users.values()

        """Buscamos si el token pasado por parámetro coincide con alguno de los de nuestros usuarios."""
        for i in lista:
            if i[0]["token"] == userToken:
                return True
        return False

    def whois(self,userToken,current=None):
        """Si no es un token autorizado se lanza la excepcion."""
        if not self.isAuthorized(userToken):
            raise IceFlix.Unauthorized

        """ Buscamos dentro de los valores de nuestro diccionario y devolvemos la clave."""
        lista = self.users.items()
        for i in lista:
            if i[1][0]["token"] == userToken:
                return i[0]

    def isAdmin(self,adminToken,current=None):  
        """Si el token no es del admin se lanza la excepcion."""
        if self.adminToken == adminToken:
            return True
        return False

    def addUser(self,user,passwordHash,adminToken,current=None): 
        """ Si el token suministrado no es el del admin, se lanza la excepcion."""
        if not self.isAdmin(adminToken):
            raise IceFlix.Unauthorized

        """ No se permiten usuarios con el mismo nombre por lo tanto, si ya existe uno, se lanza la excepcion."""
        if self.users.get(user):
            raise IceFlix.Unauthorized

        """ Guardamos el nuevo usuario y de forma persistente también."""
        self.users[user] = [{"token":secrets.token_hex(16),"passwordHash":passwordHash,
        "timestamp":time.mktime(datetime.datetime.now().timetuple())}]

        with open(PATH_USERS,'w') as fd:
            json.dump(self.users,fd)
        
        self.userUpdate.newUser(user,passwordHash,self.id)

    def removeUser(self,user,adminToken,current=None):
        """Si el token suministrado no es el del admin, se lanza la excepcion."""
        if not self.isAdmin(adminToken):
            raise IceFlix.Unauthorized
        
        """Si el usuario no existe, no se puede borrar."""
        if not self.users.get(user):
            raise IceFlix.Unauthorized

        """Borramos al usuario de nuestra estructura de datos y del archivo json."""
        self.users.pop(user)
        with open(PATH_USERS,'w') as fd:
            json.dump(self.users,fd)

        self.userUpdate.removeUser(user,self.id)
    
    def bulkUpdate(self,current=None):
        currentUsers = {}
        activeTokens = {}

        """Realizamos las transformaciones necesarias para adaptarnos a la interfaz"""
        for i in self.users.keys():
            currentUsers[i] = self.users.get(i)[0]["passwordHash"]
            if(self.users.get(i)[0]["token"] != "" and self.users.get(i)[0]["token"] != None):
                activeTokens[i] = self.users.get(i)[0]["token"]

        auth_data = IceFlix.AuthenticatorData()

        """Empacamos la información y la enviamos"""
        auth_data.adminToken = self.adminToken
        auth_data.currentUsers = currentUsers
        auth_data.activeTokens = activeTokens

        return auth_data

class UserUpdate(IceFlix.UserUpdate):
    def __init__(self,auth:Authenticator):
        self.auth = auth

    def newToken(self,user,token,serviceId,current=None):
        """Si el serviceId lo tenemos registrado y no soy yo, continuamos"""
        if(serviceId in self.auth.proxies and serviceId != self.auth.id):

            """Mostramos la información recibida"""
            print("NewToken() received from ",serviceId)

            """Refrescamos el token de nuestra base de datos"""
            self.auth.users[user] = [{"token":token,"passwordHash":self.auth.users.get(user)[0]["passwordHash"],
            "timestamp":time.mktime(datetime.datetime.now().timetuple())}]
            with open(PATH_USERS,'w') as fd:
                json.dump(self.auth.users,fd)        
        else:
            print("NewToken() from ",serviceId," ignored")

    def revokeToken(self,token,serviceId,current=None):
        """Si el serviceId lo tenemos registrado y no soy yo, continuamos"""
        if(serviceId in self.auth.proxies and serviceId != self.auth.id):

            """Mostramos la información recibida"""
            print("RevokeToken() received from ",serviceId)

            """Eliminamos el token de nuestra base de datos"""
            user = self.auth.whois(token)
            self.auth.users[user] = [{"token":"","passwordHash":self.auth.users.get(user)[0]["passwordHash"],
            "timestamp":""}]
            with open(PATH_USERS,'w') as fd:
                json.dump(self.auth.users,fd)
        else:
            print("RevokeToken() from ",serviceId," ignored")

    def newUser(self,user,passwordHash,serviceId,current=None):

        """Si el serviceId lo tenemos registrado y no soy yo, continuamos"""
        if(serviceId in self.auth.proxies and serviceId != self.auth.id):

            """Mostramos la información recibida"""
            print("NewUser() received from ",serviceId)

            """Añadimos el usuario a nuestra base de datos"""
            self.auth.users[user] = [{"token":secrets.token_hex(16),"passwordHash":passwordHash,
            "timestamp":time.mktime(datetime.datetime.now().timetuple())}]
            with open(PATH_USERS,'w') as fd:
                json.dump(self.auth.users,fd)
        else:
            print("NewUser() from ",serviceId,"ignored")

    def removeUser(self,user,serviceId,current=None):

        """Si el serviceId lo tenemos registrado y no soy yo, continuamos"""
        if(serviceId in self.auth.proxies and serviceId != self.auth.id):

            """Mostramos la información recibida"""
            print("RemoveUser() received from ",serviceId)

            """Eliminamos el usuario de nuestra base de datos"""
            self.auth.users.pop(user)
            with open(PATH_USERS,'w') as fd:
                json.dump(self.auth.users,fd)
        else:
            print("RemoveUser() from ",serviceId,"ignored")

class Announcement(IceFlix.Announcement):
    def __init__(self,auth:Authenticator):
        self.auth = auth

    def announce(self,service,serviceId,current=None):

        """Si el proxy no es el de un Authenticator o el de un Main, es ignorado"""
        if(IceFlix.AuthenticatorPrx.checkedCast(service) or IceFlix.MainPrx.checkedCast(service)):
            
            """Si es un nuevo servicio, se guarda. Si es conocido se actualiza el timestamp y sino es ignorado"""
            if(serviceId not in self.auth.proxies and serviceId != self.auth.id):
                self.auth.proxies[serviceId] = [{"service":service,
                "timestamp":time.mktime(datetime.datetime.now().timetuple())}]
                print("Service:",service,"stored")
            elif(serviceId in self.auth.proxies and serviceId != self.auth.id): 
                self.auth.proxies[serviceId] = [{"service":service,
                "timestamp":time.mktime(datetime.datetime.now().timetuple())}]
                print("Service:",service,"updated")
            else:
                print("Service:",service,"ignored")

class Server(Ice.Application):
    def run(self, argv):
        broker = self.communicator()

        adminToken = self.communicator().getProperties().getProperty('AdminToken')
        servant = Authenticator(adminToken)

        TOPIC_MANAGER = IceStorm.TopicManagerPrx.checkedCast(
            self.communicator().propertyToProxy("IceStorm.TopicManager")
        )       
        adapter = broker.createObjectAdapterWithEndpoints("AuthenticatorAdapter","tcp")
        prx = adapter.add(servant,broker.stringToIdentity("authenticator"))

        adapter.activate()

        servant_discovery = Announcement(servant)
        proxy_discovery = adapter.addWithUUID(servant_discovery)
        try:
            topic = TOPIC_MANAGER.create('Announcements')
        except:
            topic = TOPIC_MANAGER.retrieve('Announcements')
        topic.subscribeAndGetPublisher({},proxy_discovery)

        servant_updates = UserUpdate(servant)
        proxy_updates = adapter.addWithUUID(servant_updates)
        try:
            topic_updates = TOPIC_MANAGER.create('UserUpdates')
        except:
            topic_updates = TOPIC_MANAGER.retrieve('UserUpdates')
        topic_updates.subscribeAndGetPublisher({},proxy_updates)

        t = threading.Timer(12,self.startUpService,[prx,servant,topic,topic_updates])
        t.daemon = True
        t.start()

        self.shutdownOnInterrupt()
        broker.waitForShutdown()
        topic.unsubscribe(proxy_discovery)
        topic_updates.unsubscribe(proxy_updates)

        return 0

    def startUpService(self,prx,auth:Authenticator,topic,topic1):
        if(len(auth.proxies) == 0):
            print("No main found, shutting down")
            self.communicator().shutdown()
            return
            
        authenticator = None
        main = None

        for key in auth.proxies:
            value = auth.proxies.get(key)[0]["service"]
            if(IceFlix.AuthenticatorPrx.checkedCast(value)):
                authenticator = IceFlix.AuthenticatorPrx.checkedCast(value)
            elif(IceFlix.MainPrx.checkedCast(value)):
                main = IceFlix.MainPrx.checkedCast(value)

        if main == None:
            print("No main found, shutting down")
            self.communicator().shutdown()
            return

        if authenticator != None:
            print("BulkUpdate from",authenticator,"\n")
            authData = authenticator.bulkUpdate()
            auth.adminToken = authData.adminToken
            for i in authData.currentUsers:
                token = ""
                try:
                    token = authData.activeTokens.get(i)
                except KeyError:
                    pass
                auth.users[i] = [{"token":token,"passwordHash":authData.currentUsers.get(i),
                "timestamp":time.mktime(datetime.datetime.now().timetuple())}]
                with open(PATH_USERS,'w') as fd:
                    json.dump(auth.users,fd)
        else:
            print("I'm the first Authenticator, restoring DataBase\n")

        t = threading.Thread(target=self.anunciarServicio,args=(prx,auth,topic))
        t.daemon = True
        t.start()

        h = threading.Thread(target=self.revocarTokens,args=(auth,topic1))
        h.daemon = True
        h.start()

        b = threading.Thread(target=self.revokeServices,args=(auth,))
        b.daemon = True
        b.start()

    def anunciarServicio(self,prx,servant,topic):
        while True:
            publisher = topic.getPublisher()
            servant.announcement = IceFlix.AnnouncementPrx.uncheckedCast(publisher)
            servant.announcement.announce(prx,servant.id)
            time.sleep(9)

    def revokeServices(self,auth:Authenticator):
        while True:
            deleteItems = []
            for i in auth.proxies:
                if(time.mktime(datetime.datetime.now().timetuple()) - auth.proxies.get(i)[0]["timestamp"]) >= 15:
                    deleteItems.append(i)
            for i in deleteItems:
                auth.proxies.pop(i)       
            time.sleep(30)

    def revocarTokens(self,auth:Authenticator,topic):
        while True:
            publisher = topic.getPublisher()
            auth.userUpdate = IceFlix.UserUpdatePrx.uncheckedCast(publisher)
            for i in auth.users:
                if(auth.users.get(i)[0]["timestamp"] != "" and auth.users.get(i)[0]["token"] != None):
                    if (time.mktime(datetime.datetime.now().timetuple()) - auth.users.get(i)[0]["timestamp"]) >= 120:
                        auth.userUpdate.revokeToken(auth.users.get(i)[0]["token"],auth.id)
                        auth.users.get(i)[0]["token"] = ""
                        auth.users.get(i)[0]["timestamp"] = ""
                        with open(PATH_USERS,'w') as fd:
                            json.dump(auth.users,fd)
            time.sleep(30)
            
if __name__ == "__main__":
    server = Server()
    sys.exit(server.main(sys.argv))
