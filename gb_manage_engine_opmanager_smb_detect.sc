if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113336" );
	script_version( "2021-09-22T15:39:37+0000" );
	script_tag( name: "last_modification", value: "2021-09-22 15:39:37 +0000 (Wed, 22 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-02-14 14:38:37 +0100 (Thu, 14 Feb 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "ManageEngine OpManager Detection (Windows SMB Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "summary", value: "SMB login-based detection of ManageEngine OpManager." );
	script_xref( name: "URL", value: "https://www.manageengine.com/network-monitoring/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
if(!os_arch = get_kb_item( "SMB/Windows/Arch" )){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ){
	key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" );
}
else {
	if( ContainsString( os_arch, "x64" ) ){
		key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
			 "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall" );
	}
	else {
		exit( 0 );
	}
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		appName = registry_get_sz( key: key + "\\" + item, item: "DisplayName" );
		if(!IsMatchRegexp( appName, "ManageEngine OpManager" )){
			continue;
		}
		version = "unknown";
		location = "unknown";
		set_kb_item( name: "manageengine/opmanager/detected", value: TRUE );
		set_kb_item( name: "manageengine/opmanager/smb/0/detected", value: TRUE );
		loc = registry_get_sz( key: key + "\\" + item, item: "InstallLocation" );
		if(loc){
			location = loc;
			infopath = location + "\\blog\\opmunified.txt";
			file_content = smb_read_file( fullpath: infopath, offset: 0, count: 3000 );
			if(file_content){
				ver = eregmatch( string: file_content, pattern: "Build_Comment=([0-9]+)" );
				if(!isnull( ver[1] )){
					version = ver[1];
				}
			}
		}
		set_kb_item( name: "manageengine/opmanager/smb/0/version", value: version );
		set_kb_item( name: "manageengine/opmanager/smb/0/location", value: location );
		set_kb_item( name: "manageengine/opmanager/smb/0/concluded", value: ver[0] );
		exit( 0 );
	}
}
exit( 0 );

