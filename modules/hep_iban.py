from hawkeye import HawkEyeEvent, HawkEyeHelpers, HawkEyePlugin


class hep_iban(HawkEyePlugin):

    meta = {
        'name': "IBAN Number Extractor",
        'summary': "Identify International Bank Account Numbers (IBANs) in any data.",
        'flags': ["errorprone"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Content Analysis"]
    }

    opts = {
    }

    optdescs = {
    }

    results = None

    def setup(self, hec, userOpts=dict()):
        self.he = hec
        self.results = self.tempStorage()

        # Override datasource for hep_iban module
        self.__dataSource__ = "Target Website"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["TARGET_WEB_CONTENT", "DARKNET_MENTION_CONTENT",
                "LEAKSITE_CONTENT"]

    # What events this module produces
    def producedEvents(self):
        return ["IBAN_NUMBER"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        ibans = HawkEyeHelpers.extractIbansFromText(eventData)
        for ibanNumber in set(ibans):
            self.info(f"Found IBAN number: {ibanNumber}")
            evt = HawkEyeEvent("IBAN_NUMBER", ibanNumber, self.__name__, event)
            if event.moduleDataSource:
                evt.moduleDataSource = event.moduleDataSource
            else:
                evt.moduleDataSource = "Unknown"
            self.notifyListeners(evt)

# End of hep_iban class
