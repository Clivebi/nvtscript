if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107603" );
	script_version( "2021-02-15T16:07:55+0000" );
	script_tag( name: "last_modification", value: "2021-02-15 16:07:55 +0000 (Mon, 15 Feb 2021)" );
	script_tag( name: "creation_date", value: "2019-02-18 16:18:35 +0100 (Mon, 18 Feb 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "PACTware Detection (Windows SMB Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "SMB login-based detection of PACTware." );
	script_xref( name: "URL", value: "http://www.pactware.com" );
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
		app_name = registry_get_sz( key: key + item, item: "DisplayName" );
		if(!app_name || !IsMatchRegexp( app_name, "PACTware [0-9.]+" )){
			continue;
		}
		concluded = "Registry-Key:   " + key + item + "\n";
		concluded += "DisplayName:    " + app_name;
		location = "unknown";
		version = "unknown";
		loc = registry_get_sz( key: key + item, item: "InstallLocation" );
		if(loc){
			location = loc;
		}
		if(dispvers = registry_get_sz( key: key + item, item: "DisplayVersion" )){
			if( IsMatchRegexp( app_name, "SP" ) ){
				strip_vers = eregmatch( pattern: "(([0-9.]+) (SP[0-9])?)", string: app_name );
				version = strip_vers[2] + tolower( strip_vers[3] );
			}
			else {
				mod_vers = split( buffer: dispvers, sep: ".", keep: FALSE );
				vers_part = str_replace( find: "0", string: mod_vers[2], replace: ".", count: 1 );
				version = mod_vers[0] + "." + mod_vers[1] + "." + vers_part;
			}
			concluded += "\nDisplayVersion: " + dispvers;
		}
		set_kb_item( name: "pactware/pactware/detected", value: TRUE );
		register_and_report_cpe( app: app_name, ver: version, concluded: concluded, base: "cpe:/a:pactware:pactware:", expr: "^([0-9.a-z]+)", insloc: location, regService: "smb-login", regPort: 0 );
	}
}
exit( 0 );

