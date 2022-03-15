if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107408" );
	script_version( "2021-05-26T09:57:42+0000" );
	script_tag( name: "last_modification", value: "2021-05-26 09:57:42 +0000 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2018-12-08 12:31:03 +0100 (Sat, 08 Dec 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "SolarWinds Orion Network Performance Monitor (NPM) Detection (Windows SMB Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "SMB login-based detection of the SolarWinds Orion Network
  Performance Monitor (NPM)." );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("smb_nt.inc.sc");
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
		if(!appName || !IsMatchRegexp( appName, "SolarWinds Orion Network Performance Monitor" )){
			continue;
		}
		concluded = "Registry Key:   " + key + item + "\n";
		concluded += "DisplayName:    " + appName + "\n";
		location = "unknown";
		version = "unknown";
		loc = registry_get_sz( key: key + item, item: "InstallLocation" );
		if(loc){
			location = loc;
		}
		if(vers = registry_get_sz( key: key + item, item: "DisplayVersion" )){
			version = vers;
			concluded += "DisplayVersion: " + vers + "\n";
		}
		set_kb_item( name: "solarwinds/orion/npm/detected", value: TRUE );
		set_kb_item( name: "solarwinds/orion/npm/smb/detected", value: TRUE );
		set_kb_item( name: "solarwinds/orion/npm/smb/x86/version", value: version );
		set_kb_item( name: "solarwinds/orion/npm/smb/path", value: location );
		set_kb_item( name: "solarwinds/orion/npm/smb/concluded", value: concluded );
		exit( 0 );
	}
}
exit( 0 );

