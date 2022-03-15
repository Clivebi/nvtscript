if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107365" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2018-11-10 14:45:11 +0100 (Sat, 10 Nov 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "ServersCheck Monitoring Software Version Detection (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script detects the installed version
  of ServersCheck Monitoring Software for Windows." );
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
		version = "unknown";
		location = "unknown";
		if(!appName || !IsMatchRegexp( appName, "ServersCheck Monitoring Software" )){
			continue;
		}
		loc = registry_get_sz( key: key + item, item: "InstallLocation" );
		if(loc){
			location = loc;
		}
		ver = eregmatch( string: appName, pattern: "([0-9]+\\.[0-9]+\\.[0-9])$" );
		if(ver[1]){
			version = ver[1];
		}
		set_kb_item( name: "serverscheck/monitoring_software/win/detected", value: TRUE );
		set_kb_item( name: "serverscheck/monitoring_software_or_server/detected", value: TRUE );
		set_kb_item( name: "serverscheck/monitoring_software/win/ver", value: version );
		register_and_report_cpe( app: "ServersCheck Monitoring Software", ver: version, concluded: appName, base: "cpe:/a:serverscheck:monitoring_software:", expr: "^([0-9.]+)", insloc: location );
		exit( 0 );
	}
}
exit( 0 );

