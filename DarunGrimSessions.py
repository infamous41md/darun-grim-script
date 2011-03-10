import sys
import os

import DarunGrimEngine
import DarunGrimAnalyzers
import DarunGrimDatabaseWrapper
import logging
import dgGlobals

Differs = {}

#
class Manager:
    DebugLevel = 1
    SourceFileName = ''
    TargetFileName = ''
    LogFilename = None
    LogFilenameForSource = None
    LogFilenameForTarget = None

    def __init__( self, databasename, binary_store_directory, output_directory,ida_path = None ):
        self.DatabaseFilename = databasename
        self.BinariesStorageDirectory = binary_store_directory
        self.OutputDirectory = output_directory

        self.IDAPath = None
        if ida_path:
            if os.path.isfile( ida_path ):
                self.IDAPath = ida_path

        if not self.IDAPath:
            for filename in ( r'C:\Program Files\IDA\idag.exe', r'C:\Program Files (x86)\IDA\idag.exe' ):
                if os.path.isfile( filename ):
                    self.IDAPath = filename
                    break

        if not os.path.isdir( self.OutputDirectory ):
            os.makedirs( self.OutputDirectory )
    
        self.logger = logging.getLogger(dgGlobals.LOGGER_NAME)
        self.logger.debug("db file %s, binary storage dir %s, output dir %s, ida path %s" % (self.DatabaseFilename,
                    self.BinariesStorageDirectory,
                    self.OutputDirectory, self.IDAPath))
    
    def InitFileDiffByName(self, origFile, patchFile, databasename = None, reset_database = False ):

        if not databasename:
            databasename = self.GetDefaultDatabasename(origFile, patchFile)

        if reset_database:
            self.RemoveDiffer(origFile, patchFile)

        differ = None
        if origFile and patchFile and databasename:
            self.SourceFileName = origFile
            self.TargetFileName = patchFile
            differ = self.InitFileDiff(origFile, patchFile, databasename, reset_database )
            self.SetDiffer(origFile, patchFile, differ )

        return differ

    def GetDefaultDatabasename( self, source_id, target_id ):
        databasename = str( source_id ) + '_' + str( target_id ) + ".dgf"
        return databasename

    def SetDiffer( self, source_id, target_id, differ ):
        global Differs
        Differs[ str( source_id ) + '_' + str( target_id ) ] = differ

    def RemoveDiffer( self, source_id, target_id ):
        key = str( source_id ) + '_' + str( target_id )
        
        global Differs
        if Differs.has_key( key ):
            print 'Removing', key
            differ = Differs[ key ]
            del differ
            del Differs[ key ]
        
    def GetDiffer( self, source_id, target_id ):
        key = str( source_id ) + '_' + str( target_id )
        
        global Differs
        if Differs.has_key( key ):
            return Differs[ key ]

        return None

    def InitFileDiff(self, source_filename = '', target_filename = '', databasename = '', reset_database = False ):
        if self.DebugLevel > 10:
            print '='*80
            print 'source_filename=',source_filename
            print 'target_filename=',target_filename
            print 'databasename=',databasename

        base_filename = os.path.basename( source_filename )
        dot_pos = base_filename.find('.')
        if dot_pos >= 0:
            base_filename = base_filename[:dot_pos]
        
        if not databasename:
            print "ERRRRRRRRRORORORORR"
        else:
            full_databasename = databasename
            log_filename = full_databasename + ".log"
            ida_log_filename_for_source = full_databasename + "-source.log"
            ida_logfilename_for_target = full_databasename + "-target.log"

        if reset_database:
            if self.DebugLevel > 0:
                print 'Removing', full_databasename
            os.remove( full_databasename )

        differ = self.LoadDiffer( full_databasename, source_filename, target_filename )

        self.DatabaseName = full_databasename
        if not differ:
            differ = DarunGrimEngine.Differ( source_filename, target_filename )
            differ.SetIDAPath( self.IDAPath )
            if self.DebugLevel > 2:
                print 'source_filename',source_filename
                print 'target_filename',target_filename
                print 'databasename',databasename
                print 'log_filename', log_filename
                print 'ida_log_filename_for_source', ida_log_filename_for_source
                print 'ida_logfilename_for_target', ida_logfilename_for_target
            differ.DiffFile( full_databasename, log_filename, ida_log_filename_for_source, ida_logfilename_for_target )
            self.LogFilename = log_filename
            self.LogFilenameForSource = ida_log_filename_for_source
            self.LogFilenameForTarget = ida_logfilename_for_target

        self.UpdateSecurityImplicationsScore( full_databasename )

        return differ

    def LoadDiffer( self, databasename, source_filename = None, target_filename = None ):
        if os.path.isfile( databasename ) and os.path.getsize( databasename ) > 0:
            database = DarunGrimDatabaseWrapper.Database( databasename )
            function_match_info_count = database.GetFunctionMatchInfoCount()
            del database

            if function_match_info_count > 0:
                differ = DarunGrimEngine.Differ( source_filename, target_filename )
                differ.SetIDAPath( self.IDAPath )
                if self.DebugLevel > 0:
                    print 'Already analyzed',databasename
                differ.LoadDiffResults( databasename )
                return differ
        return None

    def SyncIDA( self, source_id, target_id):
        differ = self.GetDiffer( source_id, target_id )
    
        if not differ:
            differ = self.InitFileDiffByID( source_id, target_id )

        if differ:
            differ.SyncIDA();

    def ShowAddresses( self, source_id, target_id, source_address, target_address ):
        differ = self.GetDiffer( source_id, target_id )
        if differ:
            differ.ShowAddresses( source_address, target_address )

    def ColorAddresses( self, source_id, target_id, source_address_infos, target_address_infos ):
        differ = self.GetDiffer( source_id, target_id )

        if differ:
            for (source_address_start, source_address_end, match_rate) in source_address_infos:
                color = self.GetColorForMatchRate( match_rate )
                differ.ColorAddress( 0, source_address_start, source_address_end, color )
    
            for (target_address_start, target_address_end, match_rate) in target_address_infos: 
                color = self.GetColorForMatchRate( match_rate )
                differ.ColorAddress( 1, target_address_start, target_address_end, color )

    def GetColorForMatchRate( self, match_rate ):
        if match_rate == 0:
            return 0x0000ff
        elif match_rate == 100:
            return 0xffffff

        return 0x00ffff

    def UpdateSecurityImplicationsScore( self, databasename ):
        database = DarunGrimDatabaseWrapper.Database( databasename )
        pattern_analyzer = DarunGrimAnalyzers.PatternAnalyzer()
        for function_match_info in database.GetFunctionMatchInfo():
            if function_match_info.non_match_count_for_the_source > 0 or \
                function_match_info.non_match_count_for_the_target > 0 or \
                function_match_info.match_count_with_modificationfor_the_source > 0:

                function_match_info.security_implications_score = pattern_analyzer.GetSecurityImplicationsScore( 
                                            databasename,
                                            function_match_info.source_address, 
                                            function_match_info.target_address )
        database.Commit()

#
if __name__ == '__main__':
    print "HAZ NO MAIN"
