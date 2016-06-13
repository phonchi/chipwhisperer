#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2014, NewAE Technology Inc
# All rights reserved.
#
# Find this and more at newae.com - this file is part of the chipwhisperer
# project, http://www.assembla.com/spaces/chipwhisperer
#
#    This file is part of chipwhisperer.
#
#    chipwhisperer is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    chipwhisperer is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Lesser General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with chipwhisperer.  If not, see <http://www.gnu.org/licenses/>.
#=================================================

# Python standard imports
import math
import pickle
import sys
from datetime import datetime
from PySide.QtCore import *
from PySide.QtGui import *
from pyqtgraph.parametertree import ParameterTree
import chipwhisperer.common.utils.qt_tweaks as QtFixes
from chipwhisperer.common.utils.parameter import Parameterized, Parameter
from chipwhisperer.common.utils import util

class TuningParameter(Parameterized):

    def __init__(self, num):
        super(TuningParameter, self).__init__()
        self._name = 'Tuning Parameter %d' % num
        self.paramNum = num
        self.rangeComplete = util.Signal()
        self.newScriptCommand = util.Signal()
        self.nameChanged = util.Signal()
        self.tracesreqChanged = util.Signal()

        self.getParams().addChildren([
            {'name':'Name', 'type':'str', 'key':'humanname', 'value':'Param #%d' % num, 'action':lambda p:self.nameChange(p.getValue())},
            {'name':'Script Command', 'type':'str', 'key':'script', 'value':'[]', 'action':lambda p:self.updateParams()},
            {'name':'Data Format', 'type':'list', 'key':'datatype', 'values':{'Int':int, 'Float':float}, 'value':int},
            {'name':'Range', 'type':'range', 'key':'range', 'limits':(-1E6, 1E6), 'value':(0, 10), 'default':(0, 10), 'action':lambda p:self.updateParams()},
            {'name':'Value', 'type':'float', 'key':'curval', 'value':1.0},
            {'name':'Step', 'type':'float', 'key':'step', 'value':1.0, 'action':lambda p:self.updateParams()},
            {'name':'Repeat', 'type':'int', 'key':'repeat', 'value':1, 'action':lambda p:self.updateParams()},
            {'name':'Mode', 'type':'list', 'key':'mode', 'values':["Linear"], 'value':"Linear", 'action':lambda p:self.updateParams()},
        ])
        self.cnt = 0
        self.updateParams()

    def nameChange(self, newname):
        self.nameChanged.emit(self.paramNum, newname)

    def name(self):
        return self.findParam('humanname').getValue()

    def updateParams(self, ignored=None):

        rng = self.findParam('range').getValue()

        # Force to be valid values
        curval = self.findParam('curval').getValue()
        curval = max(curval, rng[0])
        self.findParam('curval').setValue(curval)

        curval = min(curval, rng[1])
        self.findParam('curval').setValue(curval)
        self.findParam('curval').setLimits(rng)

        self.paramRange = rng
        self.paramValueItem = self.findParam('curval')
        self.paramStep = self.findParam('step').getValue()
        self.paramRepeat = self.findParam('repeat').getValue()
        self.paramType = self.findParam('datatype').getValue()
        try:
            self.paramScript = eval(self.findParam('script').getValue())
        except SyntaxError, e:
            print "Syntax Error: %s" % str(e)

        self.tracesrequired = math.ceil(((self.paramRange[1] - self.paramRange[0]) / self.paramStep) * self.paramRepeat)
        self.tracesreqChanged.emit(self.paramNum, self.tracesrequired)

    def findNewValue(self, mode="linear"):
        """ Find new value for this parameter """

        if str.lower(mode) == "linear":
            self.cnt += 1
            if self.cnt == self.paramRepeat:
                # Done this one, next step
                self.cnt = 0
                newval = self.paramValueItem.getValue() + self.paramStep

                if newval > self.paramRange[1]:
                    newval = self.paramRange[0]
                    self.rangeComplete.emit(self.paramNum)

                # Cast type to required value
                newval = self.paramType(newval)

                self.paramScript[-1] = newval
                self.paramValueItem.setValue(newval)
                self.newScriptCommand.emit(self.paramNum, self.paramScript)
        else:
            raise ValueError("Unknown Increment Type %s" % mode)


class GlitchExplorerDialog(Parameterized, QtFixes.QDialog):
    _name='Glitch Explorer'

    def __init__(self, parent):
        super(GlitchExplorerDialog, self).__init__(parent)
        self.setWindowTitle("Glitch Explorer")

        self.mainLayout = QVBoxLayout()
        self.mainSplitter = QSplitter(self)
        self.mainSplitter.setOrientation(Qt.Vertical)

        self.tableList = []
        self.tuneParamList = []

        #Add default table
        self.table = QTableWidget(1,1)
        # self.table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.mainSplitter.addWidget(self.table)

        self.getParams().addChildren([
            {'name':'Clear Output Table', 'type':'action', 'action':self.clearTable},
            {'name':'Tuning Parameters', 'key':'numtune', 'type':'int', 'value':0, 'limits':(0, 4), 'action':self.updateParameters, 'readonly':False},
            {'name':'Traces Required', 'key':'tracesreq', 'type':'int', 'value':1, 'limits':(1, 1E99), 'readonly':True},
            {'name':'Normal Response', 'type':'str', 'key':'normalresp', 'value':'s.startswith("Bad")'},
            {'name':'Successful Response', 'type':'str', 'key':'successresp', 'value':'s.startswith("Welcome")'},

            {'name':'Recordings', 'type':'group', 'expanded':False, 'children':[
                # {'name':'Autosave Multi-Capture Results', 'type':'bool', 'key':'saveresults', 'value':True},
                {'name':'Last autosave Filename', 'type':'str', 'key':'savefilename', 'value':''},
                {'name':'Notes', 'type':'text', 'key':'savenotes', 'value':""},
            ]},
        ])


        self.paramTree = ParameterTree()
        self.paramTree.addParameters(self.getParams()._PyQtGraphParameter)
        self.mainSplitter.addWidget(self.paramTree)

        self.statusLabel = QLabel("")

        self.mainSplitter.addWidget(self.statusLabel)

        # self.mainSplitter.setHandleWidth(100)

        self.mainLayout.addWidget(self.mainSplitter)
        self.setLayout(self.mainLayout)
        self.hide()

        #Do an update
        self.table.setSizePolicy(QSizePolicy.MinimumExpanding, QSizePolicy.MinimumExpanding)
        self.table.horizontalHeader().setResizeMode(QHeaderView.Interactive)  # setStretchLastSection(True)
        self.clearTable()

        self._campaignRunning = False

    def tuneEnabled(self, status):
        self.findParam('numtune').setReadonly(not status)

    def campaignStart(self, prefixname):
        """Called when acqusition campaign (multi-api) starts, generates filename"""
        suffix = "_glitchresults.p"
        try:
            fname = self.parent().project().getDataFilepath(prefixname + suffix, subdirectory="glitchresults")
            self._autosavefname = fname["abs"]
        except:
            self._autosavefname = datetime.now().strftime('%Y.%m.%d-%H.%M.%S') + suffix

        self._autosavef = None
        self._campaignRunning = True
        self.tuneEnabled(False)

    def campaignDone(self):
        self._campaignRunning = False
        self.tuneEnabled(True)

        if self._autosavef:
            self._autosavef.close()
            self._autosavef = None

    def updateStatus(self):
        okcnt = 0
        for t in self.tableList:
            if t["success"]:
                okcnt += 1

        lbl = "Total %d, Glitches Successful %d" % (len(self.tableList), okcnt)
        self.statusLabel.setText(lbl)

    def clearTable(self, ignored=None):
        self.tableList = []
        self.table.clear()
        self.table.setRowCount(0)
        self.updateTableHeaders()

    def executeScriptCommand(self, paramNum, script):
        #print script
        self.parent().api.setParameter(script)

    def updateParameters(self, ignored=None):
        numparams = self.findParam('numtune').getValue()

        # Did number change? Adjust if needed
        while numparams < len(self.tuneParamList):
            #Shed parameters
            self.tuneParamList[-1].getParams().delete()
            self.tuneParamList.pop()

        while numparams > len(self.tuneParamList):
            #Add parameters
            #p = Parameter.create(name='Tuning Parameter %d' % len(self.tuneParamList), type='group', children=self.glitchTuneParamTemplate)
            p = TuningParameter(len(self.tuneParamList))
            self.tuneParamList.append(p)
            self.getParams().append(p.getParams())

            # Do stuff
            p.nameChanged.connect(self.updateTableHeaders)
            p.newScriptCommand.connect(self.executeScriptCommand)
            p.rangeComplete.connect(self.rangeDone)
            p.tracesreqChanged.connect(self.tracesreqChanged)

        self.updateTableHeaders()
        self.tracesreqChanged()
        
    def tracesreqChanged(self, pnum=None, newnum=None):
        treq = 1
        for t in self.tuneParamList:
                treq *= t.tracesrequired
        self.findParam('tracesreq').setValue(treq, ignoreReadonly=True)

    def updateTableHeaders(self, ignored=None, ignoredmore=None):

        headerlist = ["Sent", "Received", "Date"]

        for t in self.tuneParamList:
            headerlist.append(t.name())

        self.table.setColumnCount(len(headerlist))
        self.table.setHorizontalHeaderLabels(headerlist)

    def rangeDone(self, pnum):

        if (pnum + 1) < len(self.tuneParamList):
            self.tuneParamList[pnum + 1].findNewValue()

    def traceDone(self):
        """ Single api done """

        # TODO: Improve how looping is done
        if len(self.tuneParamList) > 0:
            # Always increment lowest, triggers upper values
            self.tuneParamList[0].findNewValue()

    def appendToTable(self, newdata):
        """ Append a result to the display table """

        self.table.insertRow(0)

        outdata = QTableWidgetItem(repr(newdata["output"]))

        if newdata["success"]:
            outdata.setBackground(QBrush(QColor(0,255,0)))

        elif newdata["normal"] == False:
            outdata.setBackground(QBrush(QColor(255,0,0)))

        self.table.setItem(0, 1, outdata)
        self.table.setItem(0, 2, QTableWidgetItem(newdata["date"].strftime('%H:%M:%S')))
        for i, v in enumerate(newdata["settings"]):
            self.table.setItem(0, 3 + i, QTableWidgetItem(str(v)))


    def addResponse(self, resp):
        """ Add a response from the system to glitch table + logs """

        normeval = self.findParam('normalresp').getValue()
        succeval = self.findParam('successresp').getValue()

        if len(normeval) > 0:
            #Check if Normal
            normresult = eval(normeval, {'s':resp}, {})
        else:
            normresult = False

        #Check if Successful
        if len(succeval) > 0:
            #Check if Normal
            succresult = eval(succeval, {'s':resp}, {})
        else:
            succresult = False

        #Check ?
        if isinstance(normresult, bool) == False:
            raise ValueError("Result of 'normal' eval() not a bool, got %s (result: %s)"%(type(normresult), normresult))

        if isinstance(succresult, bool) == False:
            raise ValueError("Result of 'success' eval() not a bool, got %s (result: %s)"%(type(succresult), succresult))


        if normresult and succresult:
            print "WARNING: Both normresult and succresult True!"

        starttime = datetime.now()

        respstr = str(bytearray(resp.encode('utf-8')))
        # respstr = ' '.join(["%02x" % t for t in bytearray(resp)])

        settingsList = [ self.tuneParamList[i].paramValueItem.value() for i in range(0, len(self.tuneParamList))]
        newdata = {"input":"", "output":respstr, "normal":normresult, "success":succresult, "settings":settingsList, "date":starttime}

        self.tableList.append(newdata)
        self.appendToTable(newdata)
        self.updateStatus()

        if self._campaignRunning:
            if self._autosavef is None:
                # File previously not open
                self._autosavef = open(self._autosavefname, "w")
                self.findParam('savefilename').setValue(self._autosavefname)

                # Add notes
                pickle.dump({"notes":self.findParam('savenotes').getValue()}, self._autosavef)

                # Add headers
                cmds = [self.tuneParamList[i].findParam('script').getValue() for i in range(0, len(self.tuneParamList))]
                pickle.dump({"commands":cmds}, self._autosavef)

            # Add data
            pickle.dump({"data":newdata}, self._autosavef)


def main():
    # Create the Qt Application
    app = QApplication(sys.argv)

    std = GlitchExplorerDialog(None)
    std.show()

    app.exec_()

if __name__ == '__main__':
    main()
