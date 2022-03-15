if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107644" );
	script_version( "2021-04-22T11:32:38+0000" );
	script_tag( name: "last_modification", value: "2021-04-22 11:32:38 +0000 (Thu, 22 Apr 2021)" );
	script_tag( name: "creation_date", value: "2019-04-24 12:50:31 +0200 (Wed, 24 Apr 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Delta Electronics CNCSoft A-Series Detection (Windows SMB Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "SMB login-based detection of Delta Electronics CNCSoft
  A-Series." );
	script_xref( name: "URL", value: "http://www.deltaww.com/" );
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
		if(!app_name || !IsMatchRegexp( app_name, "Delta CNC SoftMain$" )){
			found = FALSE;
			for sub_item in registry_enum_keys( key: key + item ) {
				app_name = registry_get_sz( key: key + item + "\\" + sub_item, item: "DisplayName" );
				if(app_name && ContainsString( app_name, "Delta CNC SoftMain" )){
					found = TRUE;
					item += "\\" + sub_item;
					break;
				}
			}
			if(!found){
				continue;
			}
		}
		concluded = "Registry Key:   " + key + item + "\n";
		concluded += "DisplayName:    " + app_name;
		location = "unknown";
		version = "unknown";
		loc = registry_get_sz( key: key + item, item: "UninstallString" );
		if(loc){
			split = split( buffer: loc, sep: "\\" );
			if(split && max_index( split ) > 0){
				location = ereg_replace( string: loc, pattern: split[max_index( split ) - 1], replace: "" );
				set_kb_item( name: "delta_electronics/cncsoft/a-series/location", value: location );
				filename = "CNCSoftMain.exe";
				vers = fetch_file_version( sysPath: location, file_name: filename );
				if(vers){
					version = vers;
					concluded += "\nVersion: " + version + " fetched from file " + location + filename;
				}
			}
		}
		set_kb_item( name: "delta_electronics/cncsoft/a-series/detected", value: TRUE );
		register_and_report_cpe( app: "Delta Electronics CNCSoft A-Series", ver: version, concluded: concluded, base: "cpe:/a:deltaww:cncsoft:", expr: "^([0-9.]+)", insloc: location, regService: "smb-login", regPort: 0 );
		exit( 0 );
	}
}
exit( 0 );

