from hawkeye import HawkEyePlugin


class hep__stor_db(HawkEyePlugin):

    meta = {
        'name': "Storage",
        'summary': "Stores scan results into the back-end HawkEye database. You will need this."
    }

    _priority = 0

    # Default options
    opts = {
        'maxstorage': 1024,  # max bytes for any piece of info stored (0 = unlimited)
        '_store': True
    }

    # Option descriptions
    optdescs = {
        'maxstorage': "Maximum bytes to store for any piece of information retrieved (0 = unlimited.)"
    }

    def setup(self, hec, userOpts=dict()):
        self.he = hec

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    # Because this is a storage plugin, we are interested in everything so we
    # can store all events for later analysis.
    def watchedEvents(self):
        return ["*"]

    # Handle events sent to this module
    def handleEvent(self, heEvent):
        if not self.opts['_store']:
            return

        if self.opts['maxstorage'] != 0 and len(heEvent.data) > self.opts['maxstorage']:
            self.debug("Storing an event: " + heEvent.eventType)
            self.__hedb__.scanEventStore(self.getScanId(), heEvent, self.opts['maxstorage'])
            return

        self.debug("Storing an event: " + heEvent.eventType)
        self.__hedb__.scanEventStore(self.getScanId(), heEvent)

# End of hep__stor_db class
