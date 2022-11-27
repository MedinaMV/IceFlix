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

        auth.refreshAuthorization("Octavian","Rumania")
        auth.refreshAuthorization("Alejandro","12345")
        auth.refreshAuthorization("admin","09876")
        # print(auth.isAdmin("12345"))
        # auth.refreshAuthorization("Alejandro","12345")

        self.shutdownOnInterrupt()
        broker.waitForShutdown()

        return 0

if __name__ == "__main__":
    server = Server()
    sys.exit(server.main(sys.argv))