if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802377" );
	script_version( "2021-02-17T07:02:05+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-02-17 07:02:05 +0000 (Wed, 17 Feb 2021)" );
	script_tag( name: "creation_date", value: "2012-01-12 13:49:05 +0530 (Thu, 12 Jan 2012)" );
	script_name( "Apache Tomcat Detection (Windows SMB Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "SMB login-based detection of Apache Tomcat." );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("secpod_smb_func.inc.sc");
port = kb_smb_transport();
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
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		app_name = registry_get_sz( key: key + item, item: "DisplayName" );
		if(!app_name || !IsMatchRegexp( app_name, "Apache Tomcat [0-9.]+" )){
			continue;
		}
		set_kb_item( name: "apache/tomcat/detected", value: TRUE );
		set_kb_item( name: "apache/tomcat/smb-login/detected", value: TRUE );
		concluded = "Registry Key:   " + key + item + "\n";
		concluded += "DisplayName:    " + app_name;
		location = "unknown";
		version = "unknown";
		if(vers = registry_get_sz( key: key + item, item: "DisplayVersion" )){
			version = vers;
			concluded += "\nDisplayVersion: " + vers;
		}
		loc = registry_get_sz( key: key + item, item: "UninstallString" );
		if(loc){
			split = split( buffer: loc, sep: "\\" );
			location = ereg_replace( string: loc, pattern: split[max_index( split ) - 1], replace: "" );
		}
		set_kb_item( name: "apache/tomcat/smb-login/" + port + "/installs", value: "0#---#" + location + "#---#" + version + "#---#" + concluded );
	}
}
exit( 0 );

