#!/usr/bin/env python3

import time
import datetime
import sys
import Ice
Ice.loadSlice('IceFlix.ice')
import IceFlix

class Main(IceFlix.Main):
    """Servant for the IceFlix.Main interface.

    Disclaimer: this is demo code, it lacks of most of the needed methods
    for this interface. Use it with caution
    """

    def getAuthenticator(self, current):  # pylint:disable=invalid-name, unused-argument
        "Return the stored Authenticator proxy."
        # TODO: implement
        return None

    def getCatalog(self, current):  # pylint:disable=invalid-name, unused-argument
        "Return the stored MediaCatalog proxy."
        # TODO: implement
        return None

    def newService(self, proxy, service_id, current):  # pylint:disable=invalid-name, unused-argument
        "Receive a proxy of a new service."
        print(f'Proxy received is "{proxy}" and id "{service_id}"')

    def announce(self, proxy, service_id, current):  # pylint:disable=invalid-name, unused-argument
        "Announcements handler."
        print(f'Proxy announced is "{proxy}" and id "{service_id}"')


class Server(Ice.Application):
    def run(self, argv):
        broker = self.communicator()
        servant = Main()

        adapter = broker.createObjectAdapterWithEndpoints("mainAdapter","tcp")
        prx = adapter.add(servant, broker.stringToIdentity("main"))
        
        adapter.activate()

        print(f'The proxy of main is "{prx}"')
        print(time.mktime(datetime.datetime.now().timetuple()))

        proxy = self.communicator().stringToProxy(argv[1])
        auth = IceFlix.AuthenticatorPrx.uncheckedCast(proxy)

        if not auth:
            print("No es un proxy válido de autenticacion")

        # print(auth.isAdmin("1234"))
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