if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805960" );
	script_version( "$Revision: 11015 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-08-17 08:31:19 +0200 (Fri, 17 Aug 2018) $" );
	script_tag( name: "creation_date", value: "2015-08-19 15:48:22 +0530 (Wed, 19 Aug 2015)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Netsparker Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  Netsparker.

  The script logs in via smb, searches for 'Netsparker - Web Application Security
  Scanner' in the registry and gets the version from 'DisplayVersion' string from
  registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
		key_list = make_list( "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
	}
}
if(isnull( key_list )){
	exit( 0 );
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		netName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( netName, "Netsparker - Web Application Security Scanner" )){
			netVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
			netPath = registry_get_sz( key: key + item, item: "UninstallString" );
			if( netPath ){
				netPath = netPath - "uninstall.exe";
			}
			else {
				netPath = "Unable to find the install location from registry";
			}
			if(netVer){
				set_kb_item( name: "Netsparker/Win/Ver", value: netVer );
				register_and_report_cpe( app: "Netsparker - Web Application Security Scanner", ver: netVer, base: "cpe:/a:netsparker:wass:", expr: "^([0-9.]+)", insloc: netPath );
			}
		}
	}
}

