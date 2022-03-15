if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814768" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2019-03-13 18:05:59 +0530 (Wed, 13 Mar 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Microsoft Visual Studio Code Version Detection (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script detects the installed version
  of Microsoft Visual Studio Code for Windows." );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
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
		if(ContainsString( appName, "Microsoft Visual Studio Code" )){
			version = registry_get_sz( key: key + item, item: "DisplayVersion" );
			if(!version){
				version = "Unknown";
			}
			set_kb_item( name: "microsoft_visual_studio_code/version", value: version );
			set_kb_item( name: "microsoft_visual_studio_code/installed", value: TRUE );
			location = registry_get_sz( key: key + item, item: "Inno Setup: App Path" );
			if( !location ){
				location = "Unable to find the install location from registry";
			}
			else {
				set_kb_item( name: "microsoft_visual_studio_code/location", value: location );
			}
			register_and_report_cpe( app: appName, ver: version, concluded: appName + " " + version, base: "cpe:/a:microsoft:visual_studio_code:", expr: "^([0-9.]+)", insloc: location, regService: "smb-login", regPort: 0 );
			exit( 0 );
		}
	}
}
exit( 0 );

