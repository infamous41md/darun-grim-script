#!C:\Python26\python.exe

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

#import PatchDatabaseWrapper
#import PatchTimeline
import DarunGrimSessions
import DarunGrimDatabaseWrapper
import DarunGrimAnalyzers
#import DownloadMSPatches
#import FileStore

from mako.template import Template
from HTMLPages import *

#
config_file = 'DarunGrim3.cfg'
base_dir = r'D:\projects\darun-grim-scriptable\src'

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
        return

    #
    def addDiff(self, srcVers, srcAddr, dstVers, dstAddr, changeScore = 0):

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
    def addNoMatch(self, isSrc, vers, addr):
        if isSrc:
            d = self.versions.setdefault(vers, {})
        else:
            d = self.versions.setdefault(vers, {})

        d[addr] = funcDiff(addr, vers)

    #
    def addSrc(self, vers, addr):
        return self.addNoMatch(True, vers, addr)

    #
    def addTarget(self, vers, addr):
        return self.addNoMatch(False, vers, addr)

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
            print "Invalid direction " + direction
            sys.exit(1)

        return count

    #
    def noMatchCount(self, vers, direction):
        count = self.matchCount(vers, direction)
        return len(self.versions[vers]) - count

    #
    def numFuncs(self, vers):
        info = self.versions[vers]
        s = set()
        for i in info.values():
            s.add(i.addr)
        return len(s)

    #
    def dumpFuncs(self, vers):
        info = self.versions[vers]
        for i in info.values():
            print "sub_%x" % i.addr

    #
    def showHistory(self):

        for key in sorted(self.versions.iterkeys()):
            print "File %s, %d (%d)(%d) functions" % (key, len(self.versions[key]),
                    self.numFuncs(key), len(self.versions[key]))
            #self.dumpFuncs(key)
            print "%d matched back, %d matched forward" % (self.matchCount(key, "prev"),
                                                self.matchCount(key, "next"))
            print "%d unmatched back, %d unmatched forward" % (self.noMatchCount(key, "prev"),
                                                self.noMatchCount(key, "next"))
            print "Number of changes in matched functions: %d\n" % (self.calcNumChanges(key))

    #
    def showChanges(self):

        sortedVersions = sorted(self.versions.keys())
        totalVersions = len(sortedVersions)
        firstVer = sortedVersions[0]
        lastVer = sortedVersions[-1]

        #follow the history pointers
        print "Showing history back from version [%s]" % (lastVer)
        for func in self.versions[lastVer].itervalues():
            nVersions = 1
            nChanges = 0

            fAddr = func.addr
            while func.fPrev != None:
                nVersions += 1
                nChanges += func.score
                func = func.fPrev

            print "Function %#x is present in %d/%d versions, has %d changes" % (fAddr,
                                        nVersions, totalVersions, nChanges)
#
class dgScript(object):
    DebugLevel = 0
    
    #
    def __init__(self, configFile):
        
        self.BinariesStorageDirectory = base_dir + r'\binaries'
        self.DGFDirectory = base_dir + r'\dgfs'
        self.IDAPath = None
        self.PatchTemporaryStore = 'Patches'
        self.configFile = configFile
        self.diffMan = funcDiffManager()

        #read in config file
        if os.path.exists(configFile):
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
        self.PatternAnalyzer = DarunGrimAnalyzers.PatternAnalyzer()

    #
    def GenerateDGFName(self, origFile, patchFile):
        return os.path.join(self.DGFDirectory, os.path.basename(origFile) + '_'
                                + os.path.basename(patchFile) + '.dgf')

    #
    def StartDiff( self, source_id, target_id, patch_id = 0, download_id = 0, file_id = 0,
                        show_detail = 0, reset = 'no'):
        
        databasename = self.GenerateDGFName( source_id, target_id )
        if self.DebugLevel > 5:
            print "Database name %s" % (databasename)

        reset_database = False
        if reset == 'yes':
            reset_database = True

        self.DarunGrimSessionsInstance.InitFileDiffByName( source_id, target_id, databasename, reset_database )

        database = DarunGrimDatabaseWrapper.Database( databasename )

        #Check if dgf if correct? check size entries in GetFunctionMatchInfoCount?.
        if database.GetFunctionMatchInfoCount() == 0:
            print "GOT ZERO"
            sys.exit(1)
            #Remove DatabaseName
            del database
            self.DarunGrimSessionsInstance.RemoveDiffer ( source_id, target_id )
            try:
                os.remove( self.DarunGrimSessionsInstance.DatabaseName )
            except:
                print 'Error removing database file', self.DarunGrimSessionsInstance.DatabaseName
            #Show error page?

            if self.DebugLevel > 3:
                print 'LogFilename', self.DarunGrimSessionsInstance.LogFilename
                print 'LogFilenameForSource', self.DarunGrimSessionsInstance.LogFilenameForSource
                print 'LogFilenameForTarget', self.DarunGrimSessionsInstance.LogFilenameForTarget

            log = ''
            log_for_source = ''
            log_for_target = ''
            try:
                fd = open( self.DarunGrimSessionsInstance.LogFilename )
                log = fd.read()
                fd.close()
            except:
                pass

            try:
                fd = open( self.DarunGrimSessionsInstance.LogFilenameForSource )
                log_for_source = fd.read()
                fd.close()
            except:
                pass

            try:
                fd = open( self.DarunGrimSessionsInstance.LogFilenameForTarget )
                log_for_target = fd.read()
                fd.close()
            except:
                pass

            mytemplate = Template( """<%def name="layoutdata()">
                    <title>Something is wrong with IDA execution.</title>
                    <table>
                    <tr>
                        <td><b>Log for Source(${source_filename})</b></td>
                    </tr>
                    <tr>
                        <td><pre>${log_for_source}</pre></td>
                    </tr>

                    <tr>
                        <td><b>Log for Target(${target_filename})</b></td>
                    </tr>
                    <tr>
                        <td><pre>${log_for_target}</pre></td>
                    </tr>

                    <tr>
                        <td><b>Darungrim Plugin Log</b></td>
                    </tr>
                    <tr>
                        <td><pre>${log}</pre></td>
                    </tr>
                    <table>
            </%def>
            """ + BodyHTML )

            return mytemplate.render( log = log,
                log_for_source = log_for_source,
                log_for_target = log_for_target,
                source_filename = self.DarunGrimSessionsInstance.SourceFileName,
                target_filename = self.DarunGrimSessionsInstance.TargetFileName
            )
        else:
            return self.GetFunctionMatchInfo(source_id, target_id)

    #
    def GetFunctionMatchInfo(self, source_id, target_id):
        databasename = self.GenerateDGFName(source_id, target_id)
        database = DarunGrimDatabaseWrapper.Database( databasename)
        return database.GetFunctionMatchInfo()
    
    def GetFunctionMatchInfoStr():

        """
        function_match_infos = self.GetFunctionMatchInfo()
        
        for function_match_info in database.GetFunctionMatchInfo():
            if function_match_info.non_match_count_for_the_source > 0 or \
                function_match_info.non_match_count_for_the_target > 0 or \
                function_match_info.match_count_with_modificationfor_the_source > 0:
                function_match_infos.append( function_match_info )


        mytemplate = Template( FunctionmatchInfosTemplateText )
        return mytemplate.render(
                source_file_name = source_id,
                source_file_version_string = "somevers",
                target_file_name = target_id,
                target_file_version_string = "somevers",
                patch_id = patch_id, 
                patch_name = "patch",
                download_id = download_id, 
                download_label = "bla",
                file_id = file_id, 
                file_name = "asdf",
                source_id=source_id, 
                target_id = target_id, 
                function_match_infos = function_match_infos,
                show_detail = 0,
                project_id = "some-diff"
            )
        """
        return

    def ShowFunctionMatchInfo( self, patch_id, download_id, file_id, source_id, target_id ):
        return self.GetFunctionMatchInfo( patch_id, download_id, file_id, source_id, target_id )

    def ShowBasicBlockMatchInfo( self, patch_id, download_id, file_id, source_id, target_id, source_address, target_address ):
        return self.GetDisasmComparisonTextByFunctionAddress( patch_id, download_id, file_id, source_id, target_id, source_address, target_address )

    def GetDisasmComparisonTextByFunctionAddress( self, 
            patch_id, download_id, file_id, 
            source_id, target_id, source_address, target_address, 
            source_function_name = None, target_function_name = None ):

        """
        patch_database = PatchDatabaseWrapper.Database( self.DatabaseName )
        source_file = patch_database.GetFileByID( source_id )[0]
        target_file = patch_database.GetFileByID( target_id )[0]
        """
    
        databasename = self.GenerateDGFName( source_id, target_id )
        darungrim_database = DarunGrimDatabaseWrapper.Database( databasename )

        source_address = int(source_address)
        target_address = int(target_address)

        self.DarunGrimSessionsInstance.ShowAddresses( source_id, target_id, source_address, target_address )

        if not source_function_name:
            source_function_name = darungrim_database.GetBlockName( 1, source_address )

        if not target_function_name:
            target_function_name = darungrim_database.GetBlockName( 2, target_address )
        
        comparison_table = darungrim_database.GetDisasmComparisonTextByFunctionAddress( source_address, target_address )
        text_comparison_table = []

        left_line_security_implications_score_total = 0
        right_line_security_implications_score_total = 0
        for ( left_address, left_lines, right_address, right_lines, match_rate ) in comparison_table:
            left_line_security_implications_score = 0
            right_line_security_implications_score = 0
            if (right_address == 0 and left_address !=0) or match_rate < 100 :
                ( left_line_security_implications_score, left_line_text ) = self.PatternAnalyzer.GetDisasmLinesWithSecurityImplications( left_lines, right_address == 0 )
            else:
                left_line_text = "<p>".join( left_lines )

            if (left_address == 0 and right_address !=0) or match_rate < 100 :
                ( right_line_security_implications_score, right_line_text ) = self.PatternAnalyzer.GetDisasmLinesWithSecurityImplications( right_lines, left_address == 0 )
            else:
                right_line_text = "<p>".join( right_lines )

            left_line_security_implications_score_total += left_line_security_implications_score
            right_line_security_implications_score_total += right_line_security_implications_score
            text_comparison_table.append(( left_address, left_line_text, right_address, right_line_text, match_rate ) )
        
        ( source_address_infos, target_address_infos ) = darungrim_database.GetBlockAddressMatchTableByFunctionAddress( source_address, target_address )
        self.DarunGrimSessionsInstance.ColorAddresses( source_id, target_id, source_address_infos, target_address_infos )

        mytemplate = Template( ComparisonTableTemplateText )
        return mytemplate.render(
                source_file_name = source_file.filename,
                source_file_version_string = source_file.version_string,
                target_file_name = target_file.filename,
                target_file_version_string = target_file.version_string,
                source_function_name = source_function_name, 
                target_function_name = target_function_name,
                comparison_table = text_comparison_table, 
                source_id = source_id, 
                target_id = target_id, 
                source_address = source_address,
                target_address = target_address,
                patch_id = patch_id, 
                patch_name = patch_database.GetPatchNameByID( patch_id ), 
                download_id = download_id, 
                download_label = patch_database.GetDownloadLabelByID( download_id),
                file_id = file_id,
                file_name = patch_database.GetFileNameByID( file_id ),  
            )

    #create a diff database of match information
    def addDiffs(self, matchInfo, sourceFile, patchFile):
        
        #
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
                diffMan.addDiff(sourceFile, match.source_address, patchFile, match.target_address,
                        changed)
            elif match.source_address != 0 or match.target_address != 0:
                if match.source_address != 0:
                    diffMan.addSrc(sourceFile, match.source_address)
                if match.target_address != 0:
                    diffMan.addTarget(patchFile, match.target_address)
            else:
                print "Serious error: no source or target match"
                sys.exit(1)

    #
    def showHistory(self):
        self.diffMan.showHistory()

    #
    def showChanges(self):
        self.diffMan.showChanges()

    #
    def diffDir(self, bDir, fileRegEx):
        
        #get a list of all the binaries in the target directory and sort them by version
        binaries = []
        for f in glob.glob(bDir + os.sep + fileRegEx):

            try:
                pe = pefile.PE(f)
            except pefile.PEFormatError:
                continue

            binaries.append(f)

        binaries = sorted(binaries)

        #compare each pair of binaries
        for i in xrange(len(binaries)-1):

            print "Diffing %s vs %s" % (binaries[i], binaries[i+1])
            matchInfo = self.StartDiff(binaries[i], binaries[i+1])
            self.addDiffs(matchInfo, binaries[i], binaries[i+1])

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

    #parse arguments
    try:
        opts, args = getopt.getopt(sys.argv[1:], "c:o:p:d:r:s:l:")
    except getopt.GetoptError, err:
        print str(err)
        usage(sys.argv[0])

    for o,a in opts:
        if o == "-c":
            configFile = a
        elif o == "-o":
            source = a
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
    dScript.showHistory()
    dScript.showChanges()

    if savePickle:
        f = open(savePickle, "wb")
        pickle.dump(dScript, f)
        f.close()

