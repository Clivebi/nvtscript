if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818183" );
	script_version( "2021-08-17T06:00:15+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-17 06:00:15 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-11 17:35:18 +0530 (Wed, 11 Aug 2021)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Remote Desktop Client Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  Remote Desktop Client.

  The script logs in via smb, searches for Remote Desktop Client in the
  registry and gets the version from 'DisplayVersion' string in registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
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
		rdName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( rdName, "Remote Desktop" )){
			rdPath = registry_get_sz( key: key + item, item: "InstallLocation" );
			if(!rdPath){
				rdPath = "Couldn find the install location from registry";
			}
			rdVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
			if(!rdVer){
				rdVer = "unknown";
			}
			set_kb_item( name: "remote/desktop/client/win/detected", value: TRUE );
			cpe = build_cpe( value: rdVer, exp: "^([0-9.]+)", base: "cpe:/a:microsoft:remote_desktop_connection:" );
			if(!cpe){
				cpe = "cpe:/a:microsoft:remote_desktop_connection";
			}
			if(ContainsString( os_arch, "x64" ) && !ContainsString( key, "Wow6432Node" )){
				set_kb_item( name: "remote/desktop/client/x64/win", value: TRUE );
				cpe = build_cpe( value: rdVer, exp: "^([0-9.]+)", base: "cpe:/a:microsoft:remote_desktop_connection:x64:" );
				if(!cpe){
					cpe = "cpe:/a:microsoft:remote_desktop_connection:x64";
				}
			}
			register_and_report_cpe( app: "Remote Desktop Client", ver: rdVer, concluded: "Remote Desktop Client", cpename: cpe, insloc: rdPath );
			exit( 0 );
		}
	}
}
exit( 0 );

