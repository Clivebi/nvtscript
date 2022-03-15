if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802105" );
	script_version( "$Revision: 11279 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2011-06-17 11:16:31 +0200 (Fri, 17 Jun 2011)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Symantec Backup Exec Version Detection" );
	script_tag( name: "summary", value: "Detects the installed version of Symantec Backup Exec on Windows.

The script logs in via smb, searches for Symantec Backup Exec and gets the
version from 'Version' string in registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	appName = registry_get_sz( key: key + item, item: "DisplayName" );
	ilsPath = registry_get_sz( key: key + item, item: "InstallLocation" );
	if(!ilsPath){
		ilsPath = "Couldn find the install location from registry";
	}
	if( ( eregmatch( pattern: "^Symantec Backup Exec(.*) Windows Servers$", string: appName ) ) ){
		symVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(symVer != NULL){
			set_kb_item( name: "Symantec/BackupExec/Win/Installed", value: TRUE );
			if( ContainsString( os_arch, "x64" ) ){
				set_kb_item( name: "Symantec/BackupExec64/Win/Server", value: symVer );
				register_and_report_cpe( app: appName, ver: symVer, concluded: symVer, base: "cpe:/a:symantec:veritas_backup_exec_for_windows_servers:x64:", expr: "^([0-9.]+)", insloc: ilsPath );
			}
			else {
				set_kb_item( name: "Symantec/BackupExec/Win/Server", value: symVer );
				register_and_report_cpe( app: appName, ver: symVer, concluded: symVer, base: "cpe:/a:symantec:veritas_backup_exec_for_windows_servers:", expr: "^([0-9.]+)", insloc: ilsPath );
			}
		}
	}
	else {
		if(ContainsString( appName, "Symantec Backup Exec" )){
			symVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
			if(symVer != NULL){
				set_kb_item( name: "Symantec/BackupExec/Win/Installed", value: TRUE );
				if( ContainsString( os_arch, "x64" ) ){
					if(ContainsString( appName, "2010" )){
						set_kb_item( name: "Symantec/BackupExec64/2010", value: symVer );
					}
					set_kb_item( name: "Symantec/BackupExec64/Win/Ver", value: symVer );
					register_and_report_cpe( app: appName, ver: symVer, concluded: symVer, base: "cpe:/a:symantec:backup_exec:x64:", expr: "^([0-9.]+)", insloc: ilsPath );
				}
				else {
					if(ContainsString( appName, "2010" )){
						set_kb_item( name: "Symantec/BackupExec/2010", value: symVer );
					}
					set_kb_item( name: "Symantec/BackupExec/Win/Ver", value: symVer );
					register_and_report_cpe( app: appName, ver: symVer, concluded: symVer, base: "cpe:/a:symantec:backup_exec:", expr: "^([0-9.]+)", insloc: ilsPath );
				}
			}
		}
	}
}

