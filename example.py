from chipwhisperer.common.scripts.base import UserScriptBase
# Imports from Preprocessing
import chipwhisperer.analyzer.preprocessing as preprocessing
# Imports from Capture
from chipwhisperer.analyzer.attacks.cpa import CPA
from chipwhisperer.analyzer.attacks.cpa_algorithms.progressive import CPAProgressive
import chipwhisperer.analyzer.attacks.models.AES128_8bit
from chipwhisperer.common.results.base import ResultsBase

class UserScript(UserScriptBase):
    _name = "CPA"
    _description = "Simple example of attack script using CPA Progressive"

    def __init__(self, api):
        UserScriptBase.__init__(self, api)
        self.initProject()
        self.initPreprocessing()
        self.initAnalysis()
        self.initReporting()

    def initProject(self):
        self.api.openProject(".\AES_10000t.cwp")

    def initPreprocessing(self):
       # ppMod0 = preprocessing.AddNoiseRandom.AddNoiseRandom(None, self.api.project().traceManager())
       # ppMod0.setEnabled(True)
       # ppMod0.setMaxNoise(0.005000)
       # ppMod0.init()
        self.traces =  self.api.project().traceManager()

    def initAnalysis(self):
        self.attack = CPA()
        self.attack.setAnalysisAlgorithm(CPAProgressive,chipwhisperer.analyzer.attacks.models.AES128_8bit,chipwhisperer.analyzer.attacks.models.AES128_8bit.LEAK_HD_LASTROUND_STATE)
        self.attack.setTraceStart(0)
        self.attack.setTracesPerAttack(10000)
        self.attack.setIterations(1)
        self.attack.setReportingInterval(100)
        self.attack.setTargetBytes([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
        self.attack.setTraceSource(self.traces)
        self.attack.setPointRange((0,396))

    def initReporting(self):
        # Configures the attack observers (usually a set of GUI widgets)
        self.api.getResults("Attack Settings").setAnalysisSource(self.attack)
        self.api.getResults("Correlation vs Traces in Attack").setAnalysisSource(self.attack)
        self.api.getResults("Output vs Point Plot").setAnalysisSource(self.attack)
        self.api.getResults("PGE vs Trace Plot").setAnalysisSource(self.attack)
        self.api.getResults("Results Table").setAnalysisSource(self.attack)
        self.api.getResults("Save to Files").setAnalysisSource(self.attack)
        self.api.getResults("Trace Output Plot").setTraceSource(self.traces)
        self.api.setParameter(['Results', 'Save to Files', 'Save Raw Results', True])
        self.api.setParameter(['Results', 'Save to Files', 'Save type', 'correlation'])
        #self.api.setParameter(['Results', 'PGE vs Trace Plot', 'Copy PGE Data to Clipboard', None])

    def run(self):
        self.attack.processTraces()

if __name__ == '__main__':
    import sys
    from chipwhisperer.common.api.CWCoreAPI import CWCoreAPI
    import chipwhisperer.analyzer.ui.CWAnalyzerGUI as cwa
    from chipwhisperer.common.utils.parameter import Parameter
    app = cwa.makeApplication()                     # Comment this line if you don't want to use the GUI
    Parameter.usePyQtGraph = True                   # Comment this line if you don't want to use the GUI
    api = CWCoreAPI()                               # Instantiate the API
    app.setApplicationName("Capture Scripted")    # If you DO NOT want to overwrite settings from the GUI
    gui = cwa.CWAnalyzerGUI(api)                     # Comment this line if you don't want to use the GUI
    gui.show()                                      # Comment this line if you don't want to use the GUI
    api.runScriptClass(UserScript)                  # Run the User Script

    sys.exit(app.exec_())                           # Comment this line if you don't want to use the GUI
