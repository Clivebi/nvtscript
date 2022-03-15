if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107646" );
	script_version( "2019-07-31T09:47:07+0000" );
	script_tag( name: "last_modification", value: "2019-07-31 09:47:07 +0000 (Wed, 31 Jul 2019)" );
	script_tag( name: "creation_date", value: "2019-04-23 11:30:34 +0200 (Tue, 23 Apr 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "TRAEGER INDUSTRY COMPONENTS OPCManager Version Detection (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "Detects the installed version
  of TRAEGER INDUSTRY COMPONENTS OPCManager for Windows." );
	script_xref( name: "URL", value: "https://www.traeger.de" );
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
		if(!appName || !IsMatchRegexp( appName, "OPCmanager" )){
			continue;
		}
		concluded = appName;
		location = "unknown";
		loc = registry_get_sz( key: key + item, item: "UninstallString" );
		if(loc){
			split = split( buffer: loc, sep: "\\" );
			loc1 = ereg_replace( string: loc, pattern: split[max_index( split ) - 1], replace: "\"" );
			split = split( buffer: loc1, sep: "-u " );
			loc2 = split[1];
			loc3 = ereg_replace( string: loc2, pattern: "\"", replace: "" );
			if(!isnull( loc3 )){
				location = loc3;
			}
		}
		if(!version = fetch_file_version( sysPath: location, file_name: "OPCmanager.exe" )){
			version = "unknown";
		}
		set_kb_item( name: "traeger/opcmanager/win/detected", value: TRUE );
		register_and_report_cpe( app: "TRAEGER INDUSTRY COMPONENTS " + appName, ver: version, concluded: concluded, base: "cpe:/a:traeger:opcmanager:", expr: "^([0-9.]+)", insloc: location, regService: "smb-login", regPort: 0 );
		exit( 0 );
	}
}
exit( 0 );

