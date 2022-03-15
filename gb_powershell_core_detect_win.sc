if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812742" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2018-01-30 14:45:05 +0530 (Tue, 30 Jan 2018)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "PowerShell Core Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  PowerShell Core.

  The script logs in via smb, searches for 'PowerShell' in the registry
  and gets the version from 'DisplayVersion' string from registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
if(isnull( key_list )){
	exit( 0 );
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		psName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( psName, "PowerShell" )){
			psVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
			psPath = registry_get_sz( key: key + item, item: "InstallLocation" );
			if(!psPath){
				psPath = "Couldn find the install location from registry";
			}
			if(psVer){
				set_kb_item( name: "PowerShell/Win/Ver", value: psVer );
				cpe = build_cpe( value: psVer, exp: "^([0-9.]+)", base: "cpe:/a:microsoft:powershell:" );
				if(!cpe){
					cpe = "cpe:/a:microsoft:powershell";
				}
				if(ContainsString( os_arch, "64" ) && !ContainsString( key, "Wow6432Node" )){
					set_kb_item( name: "PowerShell64/Win/Ver", value: psVer );
					cpe = build_cpe( value: psVer, exp: "^([0-9.]+)", base: "cpe:/a:microsoft:powershell:x64:" );
					if(!cpe){
						cpe = "cpe:/a:microsoft:powershell:x64";
					}
				}
				register_product( cpe: cpe, location: psPath );
				log_message( data: build_detection_report( app: "PowerShell Core", version: psVer, install: psPath, cpe: cpe, concluded: psVer ) );
				exit( 0 );
			}
		}
	}
}
exit( 0 );

