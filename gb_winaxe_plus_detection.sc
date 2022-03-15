if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107127" );
	script_version( "$Revision: 10901 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-08-10 16:09:57 +0200 (Fri, 10 Aug 2018) $" );
	script_tag( name: "creation_date", value: "2017-01-17 16:11:25 +0530 (Tue, 17 Jan 2017)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "WinaXe Plus Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  WinaXe Plus.

  The script logs in via smb, searches for WinaXe Plus in the registry and gets the version from 'DisplayVersion' string from registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
		Name = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( Name, "WinaXe_Plus" )){
			set_kb_item( name: "Winaxeplus/Win/installed", value: TRUE );
			Ver = registry_get_sz( key: key + item, item: "DisplayVersion" );
			Path = registry_get_sz( key: key + item, item: "InstallLocation" );
			if(!Path){
				Path = "Unable to find the install location from registry";
			}
			if(Ver){
				set_kb_item( name: "winaxeplus/Win/Ver", value: Ver );
				cpe = build_cpe( value: Ver, exp: "^([0-9.]+)", base: "cpe:/a:winaxe:plus:" );
				if(isnull( cpe )){
					cpe = "cpe:/a:winaxe:plus";
				}
				if(ContainsString( arch, "x64" ) && !ContainsString( Path, "x86" )){
					set_kb_item( name: "winaxeplus/Win/Ver", value: Ver );
					cpe = build_cpe( value: Ver, exp: "^([0-9.]+)", base: "cpe:/a:winaxe:plus:x64:" );
					if(isnull( cpe )){
						cpe = "cpe:/a:winaxe:plus:x64";
					}
				}
				register_product( cpe: cpe, location: Path );
				log_message( data: build_detection_report( app: "Winaxe Plus", version: Ver, install: Path, cpe: cpe, concluded: Ver ) );
			}
		}
	}
}

