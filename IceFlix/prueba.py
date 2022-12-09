#!/usr/bin/env python3

import sys
import Ice
Ice.loadSlice('IceFlix.ice')
import IceFlix

class Server(Ice.Application):
    def run(self, argv):
        broker = self.communicator()

        proxy = self.communicator().stringToProxy(argv[1])
        auth = IceFlix.AuthenticatorPrx.uncheckedCast(proxy)

        if not auth:
            print("No es un proxy válido de autenticacion")

        # print(auth.addUser("Alejandro","sadf","1234"))
        print(auth.isAuthorized("8a15d6ea157ea99b570861cb2cf5352e"))
        # auth.addUser("Diego","fdhg","1234")
        # print(auth.removeUser("Diego","1234"))
        # auth.refreshAuthorization("admin","09876")
        # auth.refreshAuthorization("Alejandro","12345")

        self.shutdownOnInterrupt()
        broker.waitForShutdown()

        return 0

if __name__ == "__main__":
    server = Server()
    sys.exit(server.main(sys.argv))