if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107402" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2018-12-07 16:38:42 +0100 (Fri, 07 Dec 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "SolarWinds Application Centric Monitor Version Detection (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script detects the installed version
  of SolarWinds Application Centric Monitor for Windows." );
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
	location = "C:\\Program Files\\SolarWinds\\Orion";
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",
			 "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
		location = "C:\\Program Files (x86)\\SolarWinds\\Orion";
	}
}
if(isnull( key_list )){
	exit( 0 );
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		appName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(!appName || !IsMatchRegexp( appName, "SolarWinds Application Centric Monitor" )){
			continue;
		}
		version = "unknown";
		concluded += "SolarWinds ACM";
		ver = eregmatch( string: appName, pattern: "([0-9.]+)" );
		if(ver[1]){
			version = ver[1];
		}
		concluded += " " + version;
		set_kb_item( name: "solarwinds/acm/win/detected", value: TRUE );
		set_kb_item( name: "solarwinds/acm/win/ver", value: version );
		register_and_report_cpe( app: appName, ver: version, concluded: concluded, base: "cpe:/a:solarwinds:application_centric_monitor:", expr: "^([0-9.]+)", insloc: location, regService: "smb-login", regPort: 0 );
		exit( 0 );
	}
}
exit( 0 );

