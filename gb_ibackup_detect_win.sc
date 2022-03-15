if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805201" );
	script_version( "2019-11-05T16:13:01+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-11-05 16:13:01 +0000 (Tue, 05 Nov 2019)" );
	script_tag( name: "creation_date", value: "2014-12-01 12:55:19 +0530 (Mon, 01 Dec 2014)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "iBackup Version Detection (Windows)" );
	script_tag( name: "summary", value: "This script detects the installed
  version of iBackup on Windows.

  The script logs in via smb, searches for iBackup in the registry
  and gets the version from file." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
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
if( ContainsString( os_arch, "x86" ) ){
	key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
}
else {
	if(ContainsString( os_arch, "x64" )){
		key = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
	}
}
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	appName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( appName, "IBackup" )){
		insloc = registry_get_sz( key: key + item, item: "InstallLocation" );
		if(insloc){
			ibackupVer = fetch_file_version( sysPath: insloc, file_name: "ib_win.exe" );
			if(ibackupVer){
				set_kb_item( name: "iBackup/Win/Ver", value: ibackupVer );
				cpe = build_cpe( value: ibackupVer, exp: "^([0-9.]+)", base: "cpe:/a:pro_softnet_corporation:ibackup:" );
				if(isnull( cpe )){
					cpe = "cpe:/a:pro_softnet_corporation:ibackup";
				}
				register_product( cpe: cpe, location: insloc );
				log_message( data: build_detection_report( app: "IBackup", version: ibackupVer, install: insloc, cpe: cpe, concluded: ibackupVer ) );
			}
		}
	}
}

