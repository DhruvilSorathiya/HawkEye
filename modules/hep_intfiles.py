from hawkeye import HawkEyeEvent, HawkEyePlugin


class hep_intfiles(HawkEyePlugin):

    meta = {
        'name': "Interesting File Finder",
        'summary': "Identifies potential files of interest, e.g. office documents, zip files.",
        'flags': [],
        'useCases': ["Footprint", "Passive"],
        'categories': ["Crawling and Scanning"]
    }

    # Default options
    opts = {
        'fileexts': ["doc", "docx", "ppt", "pptx", "pdf", 'xls', 'xlsx', 'zip']
    }

    # Option descriptions
    optdescs = {
        'fileexts': "File extensions of files you consider interesting."
    }

    results = None

    def setup(self, hec, userOpts=dict()):
        self.he = hec
        self.results = self.tempStorage()
        self.__dataSource__ = "Target Website"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["LINKED_URL_INTERNAL"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["INTERESTING_FILE"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            return

        self.results[eventData] = True

        for fileExt in self.opts['fileexts']:
            if "." + fileExt.lower() in eventData.lower():
                evt = HawkEyeEvent("INTERESTING_FILE", eventData,
                                      self.__name__, event)
                self.notifyListeners(evt)

# End of hep_intfiles class
