"""Module containing a template for a main service."""

import logging

import Ice
import sys

import IceFlix # pylint:disable=import-error


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
        # TODO: implement
        return None

    def announce(self, proxy, service_id, current):  # pylint:disable=invalid-name, unused-argument
        "Announcements handler."
        # TODO: implement
        return None


class MainApp(Ice.Application):
    """Example Ice.Application for a Main service."""

    def run(self, argv):
        """Run the application, adding the needed objects to the adapter."""
        logging.info("Running Main application")
        broker = self.communicator()
        servant = Main()

        adapter = broker.createObjectAdapterWithEndpoints("mainAdapter","tcp")
        prx = adapter.add(servant, broker.stringToIdentity("main"))

        print(f'Proxy of main is "{prx}"')
        
        adapter.activate()

        self.shutdownOnInterrupt()
        broker.waitForShutdown()

        return 0

if __name__ == "__main__":
    server = MainApp()
    sys.exit(server.main(sys.argv))
