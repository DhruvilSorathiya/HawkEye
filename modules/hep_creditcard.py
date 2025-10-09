from hawkeye import HawkEyeEvent, HawkEyeHelpers, HawkEyePlugin


class hep_creditcard(HawkEyePlugin):

    meta = {
        'name': "Credit Card Number Extractor",
        'summary': "Identify Credit Card Numbers in any data",
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

        # Override datasource for hep_creditcard module
        self.__dataSource__ = "Target Website"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DARKNET_MENTION_CONTENT", "LEAKSITE_CONTENT"]

    # What events this module produces
    def producedEvents(self):
        return ["CREDIT_CARD_NUMBER"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        creditCards = HawkEyeHelpers.extractCreditCardsFromText(eventData)

        for creditCard in set(creditCards):
            self.info(f"Found credit card number: {creditCard}")
            evt = HawkEyeEvent("CREDIT_CARD_NUMBER", creditCard, self.__name__, event)
            if event.moduleDataSource:
                evt.moduleDataSource = event.moduleDataSource
            else:
                evt.moduleDataSource = "Unknown"
            self.notifyListeners(evt)

# End of hep_creditcard class
