"""Module containing a template for a main service."""

import logging

import Ice
import sys
import uuid
import time
import threading
import IceStorm

Ice.loadSlice('IceFlix.ice')
import IceFlix # pylint:disable=import-error


class Main(IceFlix.Main):
    """Servant for the IceFlix.Main interface.

    Disclaimer: this is demo code, it lacks of most of the needed methods
    for this interface. Use it with caution
    """
    def __init__(self,current=None):
        self.id = str(uuid.uuid4())

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

class MainAnnouncement(IceFlix.Announcement):
    def __init__(self,main,current=None):
        self.main = main

    def announce(self,service,serviceId,current=None):
        if(serviceId != self.main.id):
            print("Recibido ",service)

class MainApp(Ice.Application):
    """Example Ice.Application for a Main service."""

    def run(self, argv):
        """Run the application, adding the needed objects to the adapter."""
        logging.info("Running Main application")
        broker = self.communicator()
        servant = Main()
        topic_manager_str_prx = 'IceStorm/TopicManager:tcp -p 10000'
        TOPIC_MANAGER = IceStorm.TopicManagerPrx.checkedCast(
            broker.stringToProxy(topic_manager_str_prx),
        )

        adapter = broker.createObjectAdapterWithEndpoints("mainAdapter","tcp")
        prx = adapter.add(servant, broker.stringToIdentity("main"))

        print(f'Proxy of main is "{prx}"')
        
        adapter.activate()
        
        servant_discovery = MainAnnouncement(servant)
        proxy_discovery = adapter.addWithUUID(servant_discovery)
        try:
            topic = TOPIC_MANAGER.create('Announcements')
        except:
            topic = TOPIC_MANAGER.retrieve('Announcements')
        topic.subscribeAndGetPublisher({},proxy_discovery)

        t = threading.Thread(target=self.anunsiar,args=(prx,servant,topic))
        t.start()

        self.shutdownOnInterrupt()
        broker.waitForShutdown()
        topic.unsubscribe(proxy_discovery)

        return 0

    def anunsiar(self,prx,servant,topic):
        while True:
            publisher = topic.getPublisher()
            servant.announcement = IceFlix.AnnouncementPrx.uncheckedCast(publisher)
            servant.announcement.announce(prx,servant.id)
            time.sleep(4)


if __name__ == "__main__":
    server = MainApp()
    sys.exit(server.main(sys.argv))
