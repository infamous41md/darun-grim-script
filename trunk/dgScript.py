#!C:\Python26\python.exe -u

import sys
import types
import pefile
import glob
import urllib
import unittest
import re
import os
import getopt
import pickle
import logging
import logging.handlers
import dgGlobals

import DarunGrimSessions
import DarunGrimDatabaseWrapper

from mako.template import Template

#
config_file = 'DarunGrim3.cfg'
base_dir = r'C:\Users\root\Desktop\trunk'
LOG_FILE = "darun-grim-script.log"

#match_ratio minimum to qualify as a match
MATCH_THRESHOLD = 0


#
class funcDiff:

    #
    def __init__(self, addr, ver, p = None, n = None, s = 0):
        self.addr = addr
        self.ver = ver
        self.fPrev = p
        self.fNext = n
        self.score = s

    #
    def setMatch(self, p, n):
        self.fPrev = p
        self.fNext = n

    #
    def setScore(self, s):
        self.score = s

#
class funcDiffManager:

    #
    def __init__(self):
        self.versions = {}
        self.logger = logging.getLogger(dgGlobals.LOGGER_NAME)
        return

    #
    def addDiff(self, srcVers, srcAddr, dstVers, dstAddr, changeScore = 0):

        self.logger.debug("Adding [%s, %#x] [%s, %#x]" % (srcVers, srcAddr,
                                dstVers, dstAddr))
        #get the dictionaries for each version
        srcDict = self.versions.setdefault(srcVers, {})
        dstDict = self.versions.setdefault(dstVers, {})

        #see if we already have an entry for this function in src/dst version
        if srcAddr in srcDict:
            srcMatch = srcDict[srcAddr]
        else:
            srcMatch = funcDiff(srcAddr, srcVers)
            srcDict[srcAddr] = srcMatch
        
        if dstAddr in dstDict:
            dstMatch = dstDict[dstAddr]
        else:
            dstMatch = funcDiff(dstAddr, dstVers)
            dstDict[dstAddr] = dstMatch

        #link the source and dest
        srcMatch.fNext = dstMatch
        dstMatch.fPrev = srcMatch

        dstMatch.score = changeScore

    #
    def addNoMatch(self, vers, addr):
        d = self.versions.setdefault(vers, {})
        if addr not in d:
            d[addr] = funcDiff(addr, vers)

    #
    def addSrc(self, vers, addr):
        self.logger.debug("Adding unmatched source [%s, %#x]" % (vers, addr))
        return self.addNoMatch(vers, addr)

    #
    def addTarget(self, vers, addr):
        self.logger.debug("Adding unmatched target [%s, %#x]" % (vers, addr))
        return self.addNoMatch(vers, addr)

    #
    def calcNumChanges(self, vers):
        d = self.versions[vers]
        count = 0
        for f in d.values():
            count += f.score

        return count

    #
    def matchCount(self, vers, direction):
        d = self.versions[vers]
        count = 0
        if direction == "prev":
            for f in d.values():
                if f.fPrev:
                    count += 1
        elif direction == "next":
            for f in d.values():
                if f.fNext:
                    count += 1
        else:
            self.logger.error("Invalid direction " + direction)
            sys.exit(1)

        return count

    #
    def noMatchCount(self, vers, direction):
        count = self.matchCount(vers, direction)
        return len(self.versions[vers]) - count

    #
    def numFuncs(self, vers):
        info = self.versions[vers]
        return len(info)

    #
    def dumpFuncs(self, vers):
        info = self.versions[vers]
        for i in info.values():
            self.logger.info("sub_%x" % i.addr)

    #
    def showHistory(self):

        for key in sorted(self.versions.iterkeys()):
            self.logger.info("File %s, %d functions" % (key,
                                                self.numFuncs(key)))
            #self.dumpFuncs(key)
            self.logger.info("%d matched back, %d matched forward" % (self.matchCount(key, "prev"),
                                                self.matchCount(key, "next")))
            self.logger.info("%d unmatched back, %d unmatched forward" % (self.noMatchCount(key, "prev"),
                                                self.noMatchCount(key, "next")))
            self.logger.info("Number of changes in matched functions: %d\n" % (self.calcNumChanges(key)))

    #
    def showChanges(self):

        sortedVersions = sorted(self.versions.keys())
        totalVersions = len(sortedVersions)
        firstVer = sortedVersions[0]
        lastVer = sortedVersions[-1]

        #follow the history pointers
        self.logger.info("Showing history back from version [%s]" % (lastVer))
        for fAddr in sorted(self.versions[lastVer].keys()):
            nVersions = 1
            nChanges = 0

            func = self.versions[lastVer][fAddr]
            while func.fPrev != None:
                nVersions += 1
                nChanges += func.score
                func = func.fPrev

            self.logger.info("Function %#x is present in %d/%d versions, has %d changes" % (fAddr,
                                        nVersions, totalVersions, nChanges))

    #
    def emitSVG(self):

        sortedVersions = sorted(self.versions.keys())
        totalVersions = len(sortedVersions)
        firstVer = sortedVersions[0]
        lastVer = sortedVersions[-1]

        curX = curY = 0
        width = 40
        height = 20
        maxX = 1200
        funcs = ""
        
        #follow the history pointers
        for fAddr in sorted(self.versions[lastVer].keys()):
            nVersions = 1
            nChanges = 0

            func = self.versions[lastVer][fAddr]
            while func.fPrev != None:
                nVersions += 1
                nChanges += func.score
                func = func.fPrev

            if nChanges == 0:
                color = "rgb(0,255,255)"
            else:
                color = "rgb(%d,0,0)" % (255 - (0x10*nChanges))
            
            funcs += "\n<rect width='%d' height='%d' x='%d' y='%d' tooltip='enable'" % (width, height, curX, curY)
            funcs += " style='fill:%s;stroke-width:2;stroke:rgb(0,0,0)'>" % (color)
            funcs += "<title>function %#x</title></rect>" % (fAddr)
            
            if curX == maxX:
                curX = 0
                curY += height
            else:
                curX += width

        #
        print "<svg height='%dpx' version='1.1' xmlns='http://www.w3.org/2000/svg'>" % (curY)
        print funcs
        print "</svg>"

#
class dgScript(object):
    
    #
    def __init__(self, configFile):
        
        self.BinariesStorageDirectory = base_dir + r'\binaries'
        self.DGFDirectory = base_dir + r'\dgfs'
        self.IDAPath = None
        self.PatchTemporaryStore = 'Patches'
        self.configFile = configFile
        self.diffMan = funcDiffManager()
        self.logger = logging.getLogger(dgGlobals.LOGGER_NAME)

        #read in config file
        if os.path.exists(configFile):
            self.logger.debug("Parsing config file [%s]" % configFile)
            fd = open( configFile )
            config_data = fd.read()
            fd.close()
            config = ConfigParser.RawConfigParser()
            config.readfp(io.BytesIO( config_data ))
                    
            self.BinariesStorageDirectory = config.get("Directories", "BinariesStorage")
            self.DGFDirectory = config.get("Directories", "DGFDirectory")
            self.IDAPath = config.get("Directories", "IDAPath")
            self.DatabaseName = config.get("Directories", "DatabaseName")
            self.PatchTemporaryStore = config.get("Directories", "PatchTemporaryStore")
        
        #Operation
        self.DarunGrimSessionsInstance = DarunGrimSessions.Manager( self.DatabaseName,
                                self.BinariesStorageDirectory, self.DGFDirectory, self.IDAPath )

    #
    def GenerateDGFName(self, origFile, patchFile):
        return os.path.join(self.DGFDirectory, os.path.basename(origFile) + '_'
                                + os.path.basename(patchFile) + '.dgf')

    #
    def StartDiff( self, source_id, target_id, patch_id = 0, download_id = 0, file_id = 0,
                        show_detail = 0, reset = 'no'):
        
        databasename = self.GenerateDGFName( source_id, target_id )
        self.logger.debug("Database name %s" % (databasename))

        reset_database = False
        if reset == 'yes':
            self.logger.debug("Resetting database")
            reset_database = True

        self.logger.debug("Initiating diff of %s vs %s" % (source_id, target_id))

        self.DarunGrimSessionsInstance.InitFileDiffByName( source_id, target_id, databasename, reset_database )
        
        self.logger.debug("Diff finished")

        database = DarunGrimDatabaseWrapper.Database( databasename )

        #Check if dgf if correct? check size entries in GetFunctionMatchInfoCount?.
        if database.GetFunctionMatchInfoCount() == 0:
            self.logger.error("Match count 0, are you sure plugin is installed and paths are correct?")
            sys.exit(1)
        else:
            return self.GetFunctionMatchInfo(source_id, target_id)

    #
    def GetFunctionMatchInfo(self, source_id, target_id):
        databasename = self.GenerateDGFName(source_id, target_id)
        database = DarunGrimDatabaseWrapper.Database( databasename)
        self.logger.debug("Getting function match info from db %s" % databasename)
        matchInfo = database.GetFunctionMatchInfo()
        self.logger.debug("Done getting match info")
        return matchInfo

    #
    def getCodeRange(self, binary):
        pe  = pefile.PE(binary)
        startAddr = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.BaseOfCode
        endAddr = startAddr + pe.OPTIONAL_HEADER.SizeOfCode
        return (startAddr, endAddr)
    
    #add the current diff info to the diff manager
    def addDiffs(self, matchInfo, sourceFile, patchFile):
        
        #
        self.logger.debug("Processing matches")

        srcStart, srcEnd = self.getCodeRange(sourceFile)
        patchStart, patchEnd = self.getCodeRange(patchFile)

        diffMan = self.diffMan
        for match in matchInfo:
            
            #check the match rate
            if match.match_rate > MATCH_THRESHOLD:
                if match.non_match_count_for_the_source > 0 or \
                        match.non_match_count_for_the_target > 0 or \
                        match.match_count_with_modificationfor_the_source > 0:
                    changed = 1
                else:
                    changed = 0

                if match.source_address < srcStart or match.source_address >= srcEnd \
                        or match.target_address < patchStart \
                        or match.target_address >= patchEnd:
                    continue

                diffMan.addDiff(sourceFile, match.source_address, patchFile, match.target_address,
                        changed)
            elif match.source_address != 0 or match.target_address != 0:
                if match.source_address != 0 and \
                        match.source_address >= srcStart and match.source_address < srcEnd:
                    diffMan.addSrc(sourceFile, match.source_address)
                if match.target_address != 0 and \
                        match.target_address >= patchStart and match.target_address < patchEnd:
                    diffMan.addTarget(patchFile, match.target_address)
            else:
                self.logger.error("Serious error: no source or target match")
                sys.exit(1)

    #
    def showHistory(self):
        self.diffMan.showHistory()

    #
    def showChanges(self):
        self.diffMan.showChanges()

    #
    def emitSVG(self):
        self.diffMan.emitSVG()

    #
    def diffDir(self, bDir, fileRegEx):
        
        #get a list of all the binaries in the target directory and sort them by version
        #XXX proper version using pefile
        binaries = []
        for f in glob.glob(bDir + os.sep + fileRegEx):

            try:
                pe = pefile.PE(f)
            except pefile.PEFormatError:
                continue

            binaries.append(f)

        binaries = sorted(binaries)

        self.logger.debug("Order of diffing:")
        for binary in binaries:
            self.logger.debug("Binary: " + binary)

        #compare each pair of binaries
        for i in xrange(len(binaries)-1):

            self.logger.info("Diffing %s vs %s" % (binaries[i], binaries[i+1]))
            matchInfo = self.StartDiff(binaries[i], binaries[i+1])
            self.addDiffs(matchInfo, binaries[i], binaries[i+1])
            self.logger.debug("Finished diff")

    #
    def printMatches(self, matchInfo):
        for function_match_info in matchInfo:
            if False:#function_match_info.non_match_count_for_the_source > 0 or function_match_info.non_match_count_for_the_target > 0:
            #if function_match_info.non_match_count_for_the_source > 0 or function_match_info.non_match_count_for_the_target > 0:
                #print function_match_info.id, function_match_info.source_file_id, function_match_info.target_file_id, 
                #function_match_info.end_address, 
                print function_match_info.source_function_name + hex(function_match_info.source_address) + '\t',
                print function_match_info.target_function_name + hex(function_match_info.target_address) + '\t',
                print str(function_match_info.block_type) + '\t',
                print str(function_match_info.type) + '\t',
                print str( function_match_info.match_rate ) + "%" + '\t',
                print function_match_info.match_count_for_the_source, function_match_info.non_match_count_for_the_source, function_match_info.match_count_with_modificationfor_the_source, function_match_info.match_count_for_the_target, function_match_info.non_match_count_for_the_target, function_match_info.match_count_with_modification_for_the_target
                #print database.GetFunctionDisasmLinesMap( function_match_info.source_file_id, function_match_info.source_address )
                #print database.GetMatchMapForFunction( function_match_info.source_file_id, function_match_info.source_address )
                disasm_table = database.GetDisasmComparisonTextByFunctionAddress( function_match_info.source_address, function_match_info.target_address )
                print database. GetDisasmText( disasm_table )
            elif function_match_info.match_rate != 100:
                if function_match_info.source_address == 0:
                    print "Can't match target function %s" % (function_match_info.target_function_name)
                elif function_match_info.target_address == 0:
                    print "Can't match source function %s" % (function_match_info.source_function_name)
                else:
                    print "Doubtful match-Source %s (%#x)-> Target %s (%#x) - %d,%d:%d,%d rate: %d" % ( 
                        function_match_info.source_function_name,
                        function_match_info.source_address,
                        function_match_info.target_function_name,
                        function_match_info.target_address,
                        function_match_info.match_count_for_the_source,
                        function_match_info.non_match_count_for_the_source,
                        function_match_info.match_count_for_the_target,
                        function_match_info.non_match_count_for_the_target,
                        function_match_info.match_rate)


#
def usage(pName):
    print "Usage %s: [ -c config file ] [ -o original binary ] [ -p patched binary ]\n" \
                    "\t\t[ -d directory of binaries ] [ -r filename reg ex (for directory) ]\n" \
                    "\t\t[ -l load pickle file ] [ -s save to pickle file ]\n" \
                    "\t\t[ -v debug output ]\n" \
                    % (pName)
    sys.exit(1)

#
if __name__ == '__main__':
    import ConfigParser
    import io

    #
    savePickle = loadPickle = source = target = binDir = None
    configFile = config_file
    fileRegEx = "*"

    #log debug messages to file, info messages to console
    logger = logging.getLogger(dgGlobals.LOGGER_NAME)
    logger.setLevel(logging.INFO)
    fileHandler = logging.FileHandler(LOG_FILE, mode='w')
    fileHandler.setLevel(logging.INFO)
    consoleHandler = logging.StreamHandler(sys.stdout)
    consoleHandler.setLevel(logging.INFO)
    logger.addHandler(fileHandler)
    logger.addHandler(consoleHandler)

    #parse arguments
    try:
        opts, args = getopt.getopt(sys.argv[1:], "c:o:p:d:r:s:l:v")
    except getopt.GetoptError, err:
        print str(err)
        usage(sys.argv[0])

    for o,a in opts:
        if o == "-c":
            configFile = a
        elif o == "-o":
            source = a
        elif o == "-v":
            consoleHandler.setLevel(logging.DEBUG)
            fileHandler.setLevel(logging.DEBUG)
            logger.setLevel(logging.DEBUG)
            logger.debug("Debug mode set")
        elif o == "-s":
            savePickle = a
        elif o == "-l":
            loadPickle = a
        elif o == "-p":
            target = a
        elif o == "-d":
            binDir = a
        elif o == "-r":
            fileRegEx = a
        else:
            print "Invalid option [%s] = [%s]" % (o, a)
            usage(sys.argv[0])

    #
    if not (source and target) and not binDir and not loadPickle:
        usage(sys.argv[0])

    if loadPickle:
        f = open(loadPickle, "rb")
        dScript = pickle.load(f)
        f.close()
    else:
        dScript = dgScript(configFile)
        if binDir:
            dScript.diffDir(binDir, fileRegEx)
        else:
            matchInfo = dScript.StartDiff(source, target)
            dScript.addDiffs(matchInfo, source, target)
    #
    #dScript.showHistory()
    #dScript.showChanges()
    dScript.emitSVG()

    if savePickle:
        f = open(savePickle, "wb")
        pickle.dump(dScript, f)
        f.close()

