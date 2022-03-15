if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805100" );
	script_version( "2019-11-05T16:13:01+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-11-05 16:13:01 +0000 (Tue, 05 Nov 2019)" );
	script_tag( name: "creation_date", value: "2014-11-21 09:52:53 +0530 (Fri, 21 Nov 2014)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "ALLPlayer Version Detection (Windows)" );
	script_tag( name: "summary", value: "This script detects the installed
  version of ALLPlayer.

  The script logs in via smb, searches for ALLPlayer in the registry
  and gets the version from registry or file." );
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
	if(ContainsString( appName, "ALLPlayer" ) && !ContainsString( appName, "Remote Control" )){
		insloc = registry_get_sz( key: key + item, item: "InstallLocation" );
		if(insloc){
			AllVer = fetch_file_version( sysPath: insloc, file_name: "ALLPlayer.exe" );
			if(AllVer){
				set_kb_item( name: "ALLPlayer/Win/Ver", value: AllVer );
				cpe = build_cpe( value: AllVer, exp: "^([0-9.]+)", base: "cpe:/a:allplayer:allplayer:" );
				if(isnull( cpe )){
					cpe = "cpe:/a:allplayer:allplayer";
				}
				register_product( cpe: cpe, location: insloc );
				log_message( data: build_detection_report( app: appName, version: AllVer, install: insloc, cpe: cpe, concluded: AllVer ) );
			}
		}
	}
}

