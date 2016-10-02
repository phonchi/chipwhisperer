#
# Import
#

from chipwhisperer.common.api.CWCoreAPI import CWCoreAPI  # Import the ChipWhisperer API
import chipwhisperer.capture.ui.CWCaptureGUI as cwc       # Import the ChipWhispererCapture GUI
from chipwhisperer.common.scripts.base import UserScriptBase
from chipwhisperer.common.utils.parameter import Parameter
# Imports from Preprocessing
# import chipwhisperer.analyzer.preprocessing as preprocessing
# Imports from Attack algo
from chipwhisperer.analyzer.attacks.cpa import CPA
from chipwhisperer.analyzer.attacks.cpa_algorithms.progressive import CPAProgressive
import chipwhisperer.analyzer.attacks.models.AES128_8bit
# Imports from Result base
from chipwhisperer.common.results.base import ResultsBase

class Capture(UserScriptBase):
    _name = "SAKURA-G: AES-128 FPGA Target"
    _description = "SAKURA-G Script Version"
    def run(self):
        self.api.setParameter(['Generic Settings', 'Scope Module', 'ChipWhisperer/OpenADC'])
        self.api.setParameter(['ChipWhisperer/OpenADC', 'Connection', 'FTDI (SASEBO-W/SAKURA-G)'])
        self.api.setParameter(['ChipWhisperer/OpenADC', 'FTDI (SASEBO-W/SAKURA-G)', 'Refresh Device List', None])
        self.api.setParameter(['Generic Settings', 'Target Module', 'SAKURA G'])
        self.api.setParameter(['SAKURA G', 'Connection via:', 'CW Bitstream, with OpenADC'])
        self.api.setParameter(['Generic Settings', 'Trace Format', 'ChipWhisperer/Native'])
        self.api.connect()
        lstexample = [['OpenADC', 'Trigger Setup', 'Total Samples', 400],
                      ['OpenADC', 'Trigger Setup', 'Offset', 0],
                      ['OpenADC', 'Gain Setting', 'Setting', 40],
                      ['OpenADC', 'Trigger Setup', 'Mode', 'falling edge'],
                      ['OpenADC', 'Clock Setup', 'CLKGEN Settings', 'Divide', 2],
                      ['OpenADC', 'Clock Setup', 'ADC Clock', 'Source', 'CLKGEN x1 via DCM'],
                      ['OpenADC', 'Clock Setup', 'ADC Clock', 'Reset ADC DCM', None],
                      ]
        for cmd in lstexample: self.api.setParameter(cmd)
        #Capture a set of traces and save the project
        self.api.setParameter(['Generic Settings', 'Basic', 'Key', 'Fixed'])
        self.api.setParameter(['Generic Settings', 'Acquisition Settings', 'Number of Traces', 8000])
        self.api.saveProject(".\AES_8000t.cwp")
        self.api.captureM()
        self.api.saveProject() 
		

class Attack(UserScriptBase):
    _name = "CPA"
    _description = "Simple example of attack script using CPA"
    def __init__(self, api):
        UserScriptBase.__init__(self, api)
        self.initProject()
        self.initPreprocessing()
        self.initAnalysis()
        self.initReporting()
    def initProject(self):
        self.api.openProject(".\AES_8000t.cwp")
    def initPreprocessing(self):
        self.traces =  self.api.project().traceManager()
    def initAnalysis(self):
        self.attack = CPA()
        self.attack.setAnalysisAlgorithm(CPAProgressive,chipwhisperer.analyzer.attacks.models.AES128_8bit,chipwhisperer.analyzer.attacks.models.AES128_8bit.LEAK_HD_LASTROUND_STATE)
        self.attack.setTraceStart(0)
        self.attack.setTracesPerAttack(8000)
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
    app = cwa.makeApplication()
    Parameter.usePyQtGraph = True   # Comment if you don't need the GUI
    api = CWCoreAPI()               # Instantiate the API
    api.runScriptClass(Capture)
    gui = cwa.CWAnalyzerGUI(api)    # Comment if you don't need the GUI
    gui.show()                      # Comment if you don't need the GUI
    api.runScriptClass(Attack)

    sys.exit(app.exec_())