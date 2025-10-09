import json

from hawkeye import HawkEyePlugin


class hep__stor_stdout(HawkEyePlugin):

    meta = {
        'name': "Command-line output",
        'summary': "Dumps output to standard out. Used for when a HawkEye scan is run via the command-line."
    }

    _priority = 0
    firstEvent = True

    # Default options
    opts = {
        "_format": "tab",  # tab, csv, json
        "_requested": [],
        "_showonlyrequested": False,
        "_stripnewline": False,
        "_showsource": False,
        "_csvdelim": ",",
        "_maxlength": 0,
        "_eventtypes": dict()
    }

    # Option descriptions
    optdescs = {
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

    def output(self, event):
        d = self.opts['_csvdelim']
        if type(event.data) in [list, dict]:
            data = str(event.data)
        else:
            data = event.data

        if type(data) != str:
            data = str(event.data)

        if type(event.sourceEvent.data) in [list, dict]:
            srcdata = str(event.sourceEvent.data)
        else:
            srcdata = event.sourceEvent.data

        if type(srcdata) != str:
            srcdata = str(event.sourceEvent.data)

        if self.opts['_stripnewline']:
            data = data.replace("\n", " ").replace("\r", "")
            srcdata = srcdata.replace("\n", " ").replace("\r", "")

        if "<HEURL>" in data:
            data = data.replace("<HEURL>", "").replace("</HEURL>", "")
        if "<HEURL>" in srcdata:
            srcdata = srcdata.replace("<HEURL>", "").replace("</HEURL>", "")

        if self.opts['_maxlength'] > 0:
            data = data[0:self.opts['_maxlength']]
            srcdata = srcdata[0:self.opts['_maxlength']]

        if self.opts['_format'] == "tab":
            event_type = self.opts['_eventtypes'][event.eventType]
            if self.opts['_showsource']:
                print(f"{event.module.ljust(30)}\t{event_type.ljust(45)}\t{srcdata}\t{data}")
            else:
                print(f"{event.module.ljust(30)}\t{event_type.ljust(45)}\t{data}")

        if self.opts['_format'] == "csv":
            print((event.module + d + self.opts['_eventtypes'][event.eventType] + d + srcdata + d + data))

        if self.opts['_format'] == "json":
            d = event.asDict()
            d['type'] = self.opts['_eventtypes'][event.eventType]
            if self.firstEvent:
                self.firstEvent = False
            else:
                print(",")
            print(json.dumps(d), end='')

    # Handle events sent to this module
    def handleEvent(self, heEvent):
        if heEvent.eventType == "ROOT":
            return

        if self.opts['_showonlyrequested']:
            if heEvent.eventType in self.opts['_requested']:
                self.output(heEvent)
        else:
            self.output(heEvent)

# End of hep__stor_stdout class
