import sys
import os

import DarunGrimEngine
import DarunGrimAnalyzers
import DarunGrimDatabaseWrapper
import logging
import dgGlobals


#
class Manager:

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

        if origFile and patchFile and databasename:
            self.SourceFileName = origFile
            self.TargetFileName = patchFile
            differ = self.InitFileDiff(origFile, patchFile, databasename, reset_database )
        else:
            self.logger.error("Need orig/patch file + database to continue")
            sys.exit(1)

        return differ

    def GetDefaultDatabasename( self, source_id, target_id ):
        databasename = str( source_id ) + '_' + str( target_id ) + ".dgf"
        return databasename

    def InitFileDiff(self, source_filename = '', target_filename = '', databasename = '', reset_database = False ):

        base_filename = os.path.basename( source_filename )
        dot_pos = base_filename.find('.')
        if dot_pos >= 0:
            base_filename = base_filename[:dot_pos]
        
        if not databasename:
            self.logger.error("requires database name")
            sys.exit(1)
        else:
            full_databasename = databasename
            log_filename = full_databasename + ".log"
            ida_log_filename_for_source = full_databasename + "-source.log"
            ida_logfilename_for_target = full_databasename + "-target.log"

        if reset_database:
            self.logger.debug("Removing old database [%s]" % full_databasename)
            os.remove( full_databasename )

        self.DatabaseName = full_databasename
        differ = self.isAlreadyDiffed( full_databasename, source_filename, target_filename )
        
        if not differ:
            differ = DarunGrimEngine.Differ( source_filename, target_filename )
            differ.SetIDAPath( self.IDAPath )
            differ.DiffFile( full_databasename, log_filename, ida_log_filename_for_source, ida_logfilename_for_target )

        #self.UpdateSecurityImplicationsScore( full_databasename )

        return differ
    
    #
    def isAlreadyDiffed(self, databasename, source_filename = None, target_filename = None ):
        if os.path.isfile( databasename ) and os.path.getsize( databasename ) > 0:
            database = DarunGrimDatabaseWrapper.Database( databasename )
            function_match_info_count = database.GetFunctionMatchInfoCount()
            del database

            if function_match_info_count > 0:
                differ = DarunGrimEngine.Differ( source_filename, target_filename )
                differ.SetIDAPath( self.IDAPath )
                self.logger.debug("Already analyzed, using old dgf")
                differ.LoadDiffResults( databasename )
                return differ
        else:
            return None

