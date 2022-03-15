if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107344" );
	script_version( "2020-07-30T11:52:33+0000" );
	script_tag( name: "last_modification", value: "2020-07-30 11:52:33 +0000 (Thu, 30 Jul 2020)" );
	script_tag( name: "creation_date", value: "2018-12-04 16:23:37 +0100 (Tue, 04 Dec 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "PHOENIX CONTACT AUTOMATIONWORX Software Suite Version Detection (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script detects the installed version
  of PHOENIX CONTACT AUTOMATIONWORX Software Suite for Windows." );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
require("secpod_smb_func.inc.sc");
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
		appName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(!appName || !IsMatchRegexp( appName, "AUTOMATIONWORX" )){
			continue;
		}
		concluded = "Registry Key:   " + key + item + "\n";
		concluded += "DisplayName:    " + appName;
		version = "unknown";
		location = "unknown";
		loc = registry_get_sz( key: key + item, item: "InstallLocation" );
		if(loc){
			location = loc;
		}
		regvers = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(regvers){
			match = eregmatch( string: regvers, pattern: "([0-9]+)\\.([0-9]+)" );
			if(match[0]){
				version = match[0];
			}
			concluded += "\nDisplayVersion: " + regvers + "\n";
		}
		set_kb_item( name: "phoenixcontact/automationworx_software_suite/detected", value: TRUE );
		register_and_report_cpe( app: "PHOENIX CONTACT " + appName, ver: version, concluded: concluded, base: "cpe:/a:phoenixcontact:automationworx_software_suite:", expr: "^([0-9.]+)", insloc: location );
		exit( 0 );
	}
}
exit( 0 );

