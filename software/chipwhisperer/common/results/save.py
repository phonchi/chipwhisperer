#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2013-2016, NewAE Technology Inc
# All rights reserved.
#
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
# =================================================

import copy
from datetime import datetime
import numpy as np
from chipwhisperer.analyzer.attacks._base import AttackObserver
from .base import ResultsBase
from chipwhisperer.common.utils.pluginmanager import Plugin
from chipwhisperer.common.utils.parameter import setupSetParam
from chipwhisperer.common.utils import util


class ResultsSave(ResultsBase, AttackObserver, Plugin):
    _name = "Save to Files"
    _description = "Save correlation output to files."

    def __init__(self, name=None):
        AttackObserver.__init__(self)
        self._filename = None
        self._enabled = False
        self.dataarray = None

        self.getParams().addChildren([
            {'name': 'Save Raw Results', 'type': 'bool', 'get': self.getEnabled, 'set': self.setEnabled},
            {'name': 'Save type', 'key': 'tp', 'type': 'list', 'values': ['correlation', 'pge'], 'value': 'correlation'}
        ])

    def getPrange(self, bnum, diffs):
        """Get a list of all points for a given byte number statistic"""

        prange = self._analysisSource.getPointRange(bnum)
        prange = list(prange)

        if len(diffs[0]) == 1:
            prange[0] = prange[0] + bnum

        # Certain attack types (e.g. template) don't generate an output
        # for each point value
        if (prange[1] - prange[0]) != len(diffs[0]):
            prange[1] = prange[0] + len(diffs[0])

        return range(prange[0], prange[1])

    def calculatePGE(self):
        """Calculate the Partial Guessing Entropy (PGE)"""
        if not self._analysisSource:
            raise Warning("Attack not set/executed yet")

        stats = self._analysisSource.getStatistics()
        pge = stats.pge_total
        allpge = util.DictType()

        for i in pge:
            tnum = i['trace']
            if not tnum in allpge:
                allpge[tnum] = [{'pgesum': 0, 'trials': 0} for z in range(0, stats.numSubkeys)]

            allpge[tnum][i['subkey']]['pgesum'] += i['pge']
            allpge[tnum][i['subkey']]['trials'] += 1

        for (tnum, plist) in allpge.iteritems():
            for j in plist:
                if j['trials'] > 0:
                    j['pge'] = float(j['pgesum']) / float(j['trials'])
                    print "%d "%j['trials'],
                else:
                    j['pge'] = None

        print ""

        return allpge

    def analysisUpdated(self):
        """Stats have been updated"""
        if self._enabled == False:
            return
        fmt = self.findParam('tp').getValue()

        if fmt == 'correlation':
            # ouput vs time
            data = self._analysisSource.getStatistics().diffs

            enabledlist = []
            for bnum in range(16):
                    enabledlist.append(bnum)

            xrangelist = [0] * 256
            for bnum in enabledlist:
                diffs = data[bnum]
                if diffs is not None:
                    if not hasattr(diffs[0], '__iter__'):
                        diffs = [[t] for t in diffs]

                    prange = self.getPrange(bnum, diffs)
                    xrangelist[bnum] = prange
            print "yap"
            # corr vs trace
            attackStats = self._analysisSource.getStatistics()
            # attackStats.setKnownkey(nk)
            # attackStats.findMaximums(useAbsolute=self.useAbs)

            # attackStats.diffs[i][hypkey]
            # attackStats.diffs_tnum[i]

            if self._filename is None:
                # Generate filename
                self._filename = "tempstats_%s.npy" % datetime.now().strftime('%Y%m%d_%H%M%S')

                # Generate Array
                self.dataarray = []

            # Record max & min, used as we don't know if user wanted absolute mode or not

            tempmin = np.ndarray((self._numKeys(), self._maxNumPerms()))
            tempmax = np.ndarray((self._numKeys(), self._maxNumPerms()))

            for i in range(0, self._numKeys()):
                for j in range(0, self._numPerms(i)):
                    tempmax[i][j] = np.nanmax(attackStats.diffs[i][j])
                    tempmin[i][j] = np.nanmin(attackStats.diffs[i][j])

            newdata = {"tracecnt": copy.deepcopy(attackStats.diffs_tnum), "maxlist": attackStats.maxes_list, "data": data, "xrange": xrangelist}
        else:
            if self._filename is None:
                # Generate filename
                self._filename = "tempstats_%s.npy" % datetime.now().strftime('%Y%m%d_%H%M%S')
                # Generate Array
                self.dataarray = []
            # pge vs trace
            allpge = util.DictType() # clean up
            allpge = self.calculatePGE()
            newdata = {"pge": allpge}

        self.dataarray.append(newdata)
        np.save(self._filename, self.dataarray)

    def processAnalysis(self):
        """Attack is done"""
        self._filename = None
        self.dataarray = None

    def getEnabled(self):
        return self._enabled

    @setupSetParam("Save Raw Results")
    def setEnabled(self, enabled):
        self._enabled = enabled
