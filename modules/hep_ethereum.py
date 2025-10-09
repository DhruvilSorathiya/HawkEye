import re

from hawkeye import HawkEyeEvent, HawkEyePlugin


class hep_ethereum(HawkEyePlugin):

    meta = {
        'name': "Ethereum Address Extractor",
        'summary': "Identify ethereum addresses in scraped webpages.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Content Analysis"]
    }

    # Default options
    opts = {}
    optdescs = {}

    results = None

    def setup(self, hec, userOpts=dict()):
        self.he = hec
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["TARGET_WEB_CONTENT"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["ETHEREUM_ADDRESS"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        sourceData = self.he.hashstring(eventData)

        if sourceData in self.results:
            return

        self.results[sourceData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        # thanks to https://stackoverflow.com/questions/21683680/regex-to-match-ethereum-addresses
        matches = re.findall(r"[\s:=\>](0x[a-fA-F0-9]{40})", eventData)
        for m in matches:
            self.debug("Ethereum address match: " + m)
            evt = HawkEyeEvent("ETHEREUM_ADDRESS", m, self.__name__, event)
            self.notifyListeners(evt)

# End of hep_ethereum class
