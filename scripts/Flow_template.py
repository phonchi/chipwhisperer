#
# Import
#

from chipwhisperer.common.api.CWCoreAPI import CWCoreAPI  # Import the ChipWhisperer API
import chipwhisperer.capture.ui.CWCaptureGUI as cwc       # Import the ChipWhispererCapture GUI
import os
import shutil
from chipwhisperer.common.scripts.base import UserScriptBase
from chipwhisperer.common.utils.parameter import Parameter
# Imports from Preprocessing
# import chipwhisperer.analyzer.preprocessing as preprocessing
# Imports from Attack algo
from chipwhisperer.analyzer.attacks.profiling import Profiling
from chipwhisperer.analyzer.attacks.profiling_algorithms.template import ProfilingTemplate
from chipwhisperer.analyzer.utils.Partition import PartitionHDLastRound
# Imports from Result base
from chipwhisperer.analyzer.utils.TraceExplorerScripts.PartitionDisplay import DifferenceModeSAD
from chipwhisperer.analyzer.ui.CWAnalyzerGUI import CWAnalyzerGUI

class Capture(UserScriptBase):
    _name = "SAKURA-G: Template Attack Script"
    _description = "SAKURA-G Script Version"
    def run(self):
        if os.path.isfile("tut_randkey_randplain.cwp"): os.remove("tut_randkey_randplain.cwp")
        shutil.rmtree("tut_randkey_randplain_data", ignore_errors=True)
        if os.path.isfile("tut_fixedkey_randplain.cwp"): os.remove("tut_fixedkey_randplain.cwp")
        shutil.rmtree("tut_fixedkey_randplain_data", ignore_errors=True)
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
        self.api.setParameter(['Generic Settings', 'Basic', 'Key', 'Random'])
        self.api.setParameter(['Generic Settings', 'Acquisition Settings', 'Number of Traces', 8000])
        self.api.saveProject("tut_randkey_randplain.cwp")
        self.api.captureM()
        self.api.saveProject()
        # Capture a set of traces with fixed key and save the project
        self.api.newProject()
        self.api.saveProject("tut_fixedkey_randplain.cwp")
        self.api.setParameter(['Generic Settings', 'Basic', 'Key', 'Fixed'])
        self.api.setParameter(['Generic Settings', 'Acquisition Settings', 'Number of Traces', 200])
        self.api.captureM()
        self.api.saveProject()
		

class Attack(UserScriptBase):
    _name = "CPA"
    _description = "Simple example of attack script using CPA"
    def __init__(self, api):
        self.attack = Profiling()
        self.attack.setProject(self.api.project())
        self.attack.setTraceSource(self.traces)
        self.attack.setAnalysisAlgorithm(ProfilingTemplate)
        self.attack.setTraceStart(0)
        self.attack.setTracesPerAttack(8000)
        self.attack.setIterations(1)
        self.attack.setReportingInterval(10)
        self.attack.setTargetBytes([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
        self.attack.setPointRange((0,395))
    def initAnalysis2(self):
        # Setup the Profiling algorith to perform the actual attack
        self.attack.setProject(self.api.project())
        self.attack.setTraceSource(self.traces)
        self.attack.setTracesPerAttack(200)
        self.attack.setReportingInterval(1)
    def initReporting(self):
        # Configures the attack observers (usually a set of GUI widgets)
        self.api.getResults("Attack Settings").setAnalysisSource(self.attack)
        self.api.getResults("Correlation vs Traces in Attack").setAnalysisSource(self.attack)
        self.api.getResults("Output vs Point Plot").setAnalysisSource(self.attack)
        self.api.getResults("PGE vs Trace Plot").setAnalysisSource(self.attack)
        self.api.getResults("Results Table").setAnalysisSource(self.attack)
        self.api.getResults("Save to Files").setAnalysisSource(self.attack)
        self.api.getResults("Trace Output Plot").setTraceSource(self.traces)
        self.api.getResults("Trace Recorder").setTraceSource(self.traces)
        #self.api.setParameter(['Results', 'PGE vs Trace Plot', 'Copy PGE Data to Clipboard', None])
    def run(self):
        # This is what the API will execute
        self.api.openProject("tut_randkey_randplain.cwp")
        self.traces = self.api.project().traceManager()
        self.initAnalysis()
        self.initReporting()
        self.generateTemplates()
        self.api.saveProject()
        template = self.api.project().getDataConfig(sectionName="Template Data", subsectionName="Templates")
        self.api.openProject("tut_fixedkey_randplain.cwp")
        self.api.project().addDataConfig(template[-1], sectionName="Template Data", subsectionName="Templates")
        self.traces = self.api.project().traceManager()
        self.initAnalysis2()
        self.attack.processTraces()

        # Delete all pending scripts executions (that are observing the api to be available again),
        # otherwise the current setup would be overridden
        self.api.executingScripts.disconnectAll()


    def TraceExplorerDialog_PartitionDisplay_displayPartitionStats(self):
        self.cwagui = CWAnalyzerGUI.getInstance()
        ted = self.cwagui.attackScriptGen.utilList[0].exampleScripts[0]
        ted.setTraceSource(self.traces)
        progressBar = ted.parent.getProgressIndicator()
        ted.partObject.setPartMethod(PartitionHDLastRound)
        partData = ted.partObject.generatePartitions(saveFile=True, loadFile=False)
        partStats = ted.generatePartitionStats(partitionData={"partclass": PartitionHDLastRound, "partdata": partData},
                                               saveFile=True, progressBar=progressBar)
        partDiffs = ted.generatePartitionDiffs(DifferenceModeSAD,
                                               statsInfo={"partclass": PartitionHDLastRound, "stats": partStats},
                                               saveFile=True, loadFile=False, progressBar=progressBar)
        ted.displayPartitions(differences={"partclass": PartitionHDLastRound, "diffs": partDiffs})
        ted.poi.setDifferences(partDiffs)


    def TraceExplorerDialog_PartitionDisplay_findPOI(self):
        # Calculate the POIs
        self.cwagui = CWAnalyzerGUI.getInstance()
        ted = self.cwagui.attackScriptGen.utilList[0].exampleScripts[0]
        return ted.poi.calcPOI(numMax=3, pointRange=(0, 396), minSpace=5)['poi']


    def generateTemplates(self):
        # Generate the templates and save to the project
        self.TraceExplorerDialog_PartitionDisplay_displayPartitionStats()
        tRange = (0, 7999)
        poiList = self.TraceExplorerDialog_PartitionDisplay_findPOI()
        partMethod = PartitionHDLastRound()
        templatedata = self.attack.attack.profiling.generate(tRange, poiList, partMethod)
        tfname = self.attack.attack.saveTemplatesToProject(tRange, templatedata)

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