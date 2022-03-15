if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800217" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "$Revision: 14329 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 14:57:49 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2009-01-08 14:06:04 +0100 (Thu, 08 Jan 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Microsoft Money Version Detection" );
	script_tag( name: "summary", value: "Detects the installed version of Microsoft Money on Windows.

  The script logs in via smb, searches for Microsoft Money in the registry
  and gets the version from registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
osArch = get_kb_item( "SMB/Windows/Arch" );
if(!osArch){
	exit( 0 );
}
if( ContainsString( osArch, "x86" ) ){
	key_list = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
}
else {
	if(ContainsString( osArch, "x64" )){
		key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",
			 "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
	}
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		if(ContainsString( registry_get_sz( key: key + item, item: "DisplayName" ), "Microsoft Money" )){
			name = registry_get_sz( key: key + item, item: "DisplayName" );
			InstallPath = registry_get_sz( key: key + item, item: "InstallLocation" );
			if(!InstallPath){
				InstallPath = "Couldn find the install location from registry";
			}
			ver = eregmatch( pattern: "Microsoft Money ([0-9]+)", string: name );
			if(ver[1] != NULL){
				set_kb_item( name: "MS/Money/Win/Installed", value: TRUE );
				if( ContainsString( osArch, "x64" ) && !ContainsString( key, "Wow6432Node" ) ){
					set_kb_item( name: "MS/Money64/Win/Version", value: ver[1] );
					register_and_report_cpe( app: "Microsoft Money", ver: ver[1], base: "cpe:/a:microsoft:money:x64:", expr: "^([0-9]+)", insloc: InstallPath );
				}
				else {
					set_kb_item( name: "MS/Money/Win/Version", value: ver[1] );
					register_and_report_cpe( app: "Microsoft Money", ver: ver[1], base: "cpe:/a:microsoft:money:", expr: "^([0-9]+)", insloc: InstallPath );
				}
			}
		}
	}
}

