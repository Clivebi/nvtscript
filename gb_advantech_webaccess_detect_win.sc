if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107636" );
	script_version( "2020-05-20T06:37:45+0000" );
	script_tag( name: "last_modification", value: "2020-05-20 06:37:45 +0000 (Wed, 20 May 2020)" );
	script_tag( name: "creation_date", value: "2019-04-06 13:42:55 +0200 (Sat, 06 Apr 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Advantech Webaccess Version Detection (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "Detects the installed version
  of Advantech Webaccess for Windows." );
	script_xref( name: "URL", value: "https://www.advantech.com/" );
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
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		appName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(!appName || !IsMatchRegexp( appName, "WebAccess Node" )){
			continue;
		}
		set_kb_item( name: "advantech/webaccess/detected", value: TRUE );
		set_kb_item( name: "advantech/webaccess/smb/0/detected", value: TRUE );
		concluded = "\n  Registry Key:   " + key + item + "\n";
		concluded += "  DisplayName:    " + appName;
		location = "unknown";
		version = "unknown";
		if(vers = registry_get_sz( key: key + item, item: "DisplayVersion" )){
			concluded += "\n  DisplayVersion: " + vers;
			match = eregmatch( string: vers, pattern: "^(([0-9.]+)([P0-9]+)?)" );
			if(match[1]){
				version = match[1];
			}
		}
		set_kb_item( name: "advantech/webaccess/smb/0/concluded", value: concluded );
		set_kb_item( name: "advantech/webaccess/smb/0/version", value: version );
		loc = registry_get_sz( key: key + item, item: "InstallLocation" );
		if(loc){
			location = loc;
		}
		set_kb_item( name: "advantech/webaccess/smb/0/location", value: location );
		exit( 0 );
	}
}
exit( 0 );

