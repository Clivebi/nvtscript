if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807247" );
	script_version( "$Revision: 11279 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2016-02-11 17:49:15 +0530 (Thu, 11 Feb 2016)" );
	script_name( "Oracle GoldenGate Version Detection" );
	script_tag( name: "summary", value: "Detects the installed version of
  Oracle GoldenGate.

  The script logs in via smb, searches for Oracle GoldenGate in the registry
  and gets the version from 'DisplayName' string from registry." );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
if( ContainsString( os_arch, "x86" ) ){
	key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",
			 "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
	}
}
if(isnull( key_list )){
	exit( 0 );
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		oraName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( oraName, "Oracle GoldenGate" )){
			version = eregmatch( pattern: "([0-9.]+)", string: oraName );
			if(version[0]){
				oraVer = version[0];
			}
			if(oraVer){
				oraPath = registry_get_sz( key: key + item, item: "UninstallString" );
				if(oraPath){
					oraPath = oraPath - "\\uninstall.exe";
				}
				if(!oraPath){
					oraPath = "Unable to find the install location from registry";
				}
				set_kb_item( name: "Oracle/GoldenGate/Win/Installed", value: TRUE );
				if( ContainsString( os_arch, "64" ) && !ContainsString( key, "Wow6432Node" ) ){
					set_kb_item( name: "Oracle/GoldenGate64/Win/Ver", value: oraVer );
					register_and_report_cpe( app: "Oracle GoldenGate", ver: oraVer, base: "cpe:/a:oracle:goldengate:x64:", expr: "^([0-9.]+)", insloc: oraPath );
				}
				else {
					set_kb_item( name: "Oracle/GoldenGate/Win/Ver", value: oraVer );
					register_and_report_cpe( app: "Oracle GoldenGate", ver: oraVer, base: "cpe:/a:oracle:goldengate:", expr: "^([0-9.]+)", insloc: oraPath );
				}
				exit( 0 );
			}
		}
	}
}

