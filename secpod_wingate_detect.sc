if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900324" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-03-26 11:19:12 +0100 (Thu, 26 Mar 2009)" );
	script_name( "Qbik WinGate Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "Detects the installed version of Qbik WinGate.

  The script logs in via smb, searches for Qbik WinGate in the registry and
  gets the version from registry." );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
osArch = get_kb_item( "SMB/Windows/Arch" );
if(!osArch){
	exit( 0 );
}
if( ContainsString( osArch, "x86" ) ){
	key_list = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
}
else {
	if(ContainsString( osArch, "x64" )){
		key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",
			 "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
	}
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		appName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( appName, "WinGate" )){
			appLoc = registry_get_sz( key: key + item, item: "InstallLocation" );
			if(!appLoc){
				exit( 0 );
			}
			winGateVer = fetch_file_version( sysPath: appLoc, file_name: "WinGate.exe" );
			if(winGateVer){
				set_kb_item( name: "WinGate/Ver", value: winGateVer );
				cpe = build_cpe( value: winGateVer, exp: "^([0-9.]+)", base: "cpe:/a:qbik:wingate:" );
				if(isnull( cpe )){
					cpe = "cpe:/a:qbik:wingate";
				}
				if(ContainsString( osArch, "x64" ) && !ContainsString( key, "Wow6432Node" )){
					set_kb_item( name: "WinGate64/Ver", value: winGateVer );
					cpe = build_cpe( value: winGateVer, exp: "^([0-9.]+)", base: "cpe:/a:qbik:wingate:x64:" );
					if(isnull( cpe )){
						cpe = "cpe:/a:qbik:wingate:x64";
					}
				}
				register_product( cpe: cpe, location: appLoc );
				log_message( data: build_detection_report( app: appName, version: winGateVer, install: appLoc, cpe: cpe, concluded: winGateVer ) );
			}
		}
	}
}

