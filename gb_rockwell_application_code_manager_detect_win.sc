if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107470" );
	script_version( "2021-01-15T07:13:31+0000" );
	script_tag( name: "last_modification", value: "2021-01-15 07:13:31 +0000 (Fri, 15 Jan 2021)" );
	script_tag( name: "creation_date", value: "2019-01-19 11:15:28 +0100 (Sat, 19 Jan 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Rockwell Automation Application Code Manager Detection (Windows SMB Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "SMB login-based detection of Rockwell Automation Application Code Manager." );
	script_xref( name: "URL", value: "https://www.rockwellautomation.com" );
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
		if(!appName || !IsMatchRegexp( appName, "Application Code Manager" )){
			continue;
		}
		version = "unknown";
		concluded = appName;
		location = "unknown";
		loc = registry_get_sz( key: key + item, item: "DisplayIcon" );
		if(loc){
			split = split( buffer: loc, sep: "\\" );
			location = ereg_replace( string: loc, pattern: split[max_index( split ) - 1], replace: "" );
		}
		version = registry_get_sz( key: key + item, item: "DisplayVersion" );
		set_kb_item( name: "rockwellautomation/application_code_manager/win/detected", value: TRUE );
		register_and_report_cpe( app: "Rockwell Automation " + appName, ver: version, concluded: concluded, base: "cpe:/a:rockwellautomation:application_code_manager:", expr: "^([0-9.]+)", insloc: location, regService: "smb-login", regPort: 0 );
		exit( 0 );
	}
}
exit( 0 );

