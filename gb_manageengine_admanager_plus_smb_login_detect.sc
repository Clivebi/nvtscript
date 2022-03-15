if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107129" );
	script_version( "2021-09-28T14:43:50+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-28 14:43:50 +0000 (Tue, 28 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-01-18 16:11:25 +0700 (Wed, 18 Jan 2017)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "ManageEngine ADManager Plus Detection (Windows SMB Login)" );
	script_tag( name: "summary", value: "SMB login-based detection of ManageEngine ADManager Plus." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("host_details.inc.sc");
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
arch = get_kb_item( "SMB/Windows/Arch" );
if(!arch){
	exit( 0 );
}
if( ContainsString( arch, "x86" ) ){
	key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
}
else {
	if(ContainsString( arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",
			 "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
	}
}
if(isnull( key_list )){
	exit( 0 );
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		app_name = registry_get_sz( key: key + item, item: "DisplayName" );
		if(!app_name || !ContainsString( app_name, "ADManager Plus" )){
			continue;
		}
		concluded = "  Registry Key:   " + key + item + "\n";
		concluded += "  DisplayName:    " + app_name;
		location = "unknown";
		version = "unknown";
		build = "unknown";
		if(loc = registry_get_sz( key: key + item, item: "InstallLocation" )){
			location = loc;
			path = location + "\\conf\\product.conf";
			version_info = smb_read_file( fullpath: path, offset: 0, count: 300 );
			versq = eregmatch( pattern: "product\\.version=([0-9.]+)", string: version_info );
			buildq = eregmatch( pattern: "product\\.build_number=([0-9.]+)", string: version_info );
			if(versq[1]){
				vers = eregmatch( string: versq[1], pattern: "^([0-9]+\\.[0-9]+)" );
				if(vers[1]){
					version = vers[1];
					concluded += "\n  Version:        " + version + " (extracted from " + path + ")";
				}
			}
			if(buildq[1]){
				build = buildq[1];
				concluded += "\n  Build:          " + build + " (extracted from " + path + ")";
			}
		}
		if(regvers = registry_get_sz( key: key + item, item: "DisplayVersion" )){
			concluded += "\n  DisplayVersion: " + regvers;
		}
		set_kb_item( name: "manageengine/admanager_plus/detected", value: TRUE );
		set_kb_item( name: "manageengine/admanager_plus/smb-login/0/detected", value: TRUE );
		set_kb_item( name: "manageengine/admanager_plus/smb-login/0/location", value: location );
		set_kb_item( name: "manageengine/admanager_plus/smb-login/0/version", value: version );
		set_kb_item( name: "manageengine/admanager_plus/smb-login/0/build", value: build );
		set_kb_item( name: "manageengine/admanager_plus/smb-login/0/concluded", value: concluded );
	}
}
exit( 0 );

