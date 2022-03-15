if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801795" );
	script_version( "2021-02-05T13:29:15+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-02-05 13:29:15 +0000 (Fri, 05 Feb 2021)" );
	script_tag( name: "creation_date", value: "2011-06-07 13:29:28 +0200 (Tue, 07 Jun 2011)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Python Detection (SMB Login / Windows)" );
	script_tag( name: "summary", value: "SMB login-based detection of Python on Windows." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("host_details.inc.sc");
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
		key_list = make_list( "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",
			 "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
	}
}
if(isnull( key_list )){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\Python" )){
	if(!registry_key_exists( key: "SOFTWARE\\Wow6432Node\\Python" )){
		exit( 0 );
	}
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		name = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( name, "Python Launcher" )){
			continue;
		}
		if(IsMatchRegexp( name, "Python [0-9a-z.]+ (Executables |)\\([0-9]+-bit\\)" )){
			path = registry_get_sz( key: key + item, item: "DisplayIcon" );
			if( !path ) {
				path = "unknown";
			}
			else {
				path = path - "python.exe";
			}
			if(vers = eregmatch( pattern: "Python ([0-9a-z.]+)", string: name )){
				version = vers[1];
				if(full_vers = registry_get_sz( key: key + item, item: "DisplayVersion" )){
					set_kb_item( name: "python/smb-login/full_version", value: full_vers );
				}
				set_kb_item( name: "python/detected", value: TRUE );
				set_kb_item( name: "python/smb-login/detected", value: TRUE );
				set_kb_item( name: "python/smb-login/port", value: port );
				if( ContainsString( os_arch, "x64" ) && !ContainsString( key, "Wow6432Node" ) ){
					set_kb_item( name: "python64/smb-login/detected", value: TRUE );
				}
				else {
					set_kb_item( name: "python32/smb-login/detected", value: TRUE );
				}
				set_kb_item( name: "python/smb-login/" + port + "/installs", value: "0#---#" + path + "#---#" + version + "#---#" + name );
			}
		}
	}
}
exit( 0 );

