if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107454" );
	script_version( "2021-07-28T15:05:44+0000" );
	script_tag( name: "last_modification", value: "2021-07-28 15:05:44 +0000 (Wed, 28 Jul 2021)" );
	script_tag( name: "creation_date", value: "2019-01-17 10:25:47 +0100 (Thu, 17 Jan 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "LCDS LAquis SCADA Detection (Windows SMB Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "SMB login-based detection of LCDS LAquis SCADA." );
	script_xref( name: "URL", value: "https://laquisscada.com/" );
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
		if(!app_name || !IsMatchRegexp( app_name, "SCADA LAquis" )){
			continue;
		}
		concluded = "Registry Key:   " + key + item + "\n";
		concluded += "DisplayName:    " + app_name;
		location = "unknown";
		version = "unknown";
		regversion = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(regversion){
			concluded += "\nDisplayVersion: " + regversion;
		}
		loc = registry_get_sz( key: key + item, item: "InstallLocation" );
		if(loc){
			location = loc;
			file = "aq.exe";
			vers = fetch_file_version( sysPath: location, file_name: file );
			if(vers && IsMatchRegexp( vers, "^[0-9.]{3,}" )){
				version = vers;
				concluded += "\nFileversion:    " + vers + " fetched from " + location + file;
			}
		}
		set_kb_item( name: "lcds/laquis_scada/detected", value: TRUE );
		register_and_report_cpe( app: app_name, ver: version, concluded: concluded, base: "cpe:/a:lcds:laquis_scada:", expr: "^([0-9.]+)", insloc: location, regService: "smb-login", regPort: 0 );
		exit( 0 );
	}
}
exit( 0 );

