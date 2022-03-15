if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900072" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-04-11 14:40:00 +0200 (Mon, 11 Apr 2011)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "OpenOffice Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  OpenOffice.

  The script logs in via smb, searches for OpenOffice in the registry and gets
  the version from 'DisplayVersion' string from registry." );
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
require("cpe.inc.sc");
require("host_details.inc.sc");
osArch = get_kb_item( "SMB/Windows/Arch" );
if(!osArch){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\OpenOffice.org" )){
	if(!registry_key_exists( key: "SOFTWARE\\OpenOffice" )){
		if(!registry_key_exists( key: "SOFTWARE\\Wow6432Node\\OpenOffice.org" )){
			if(!registry_key_exists( key: "SOFTWARE\\Wow6432Node\\OpenOffice" )){
				exit( 0 );
			}
		}
	}
}
if( ContainsString( osArch, "x86" ) ){
	key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
}
else {
	if(ContainsString( osArch, "x64" )){
		key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",
			 "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
	}
}
if(isnull( key_list )){
	exit( 0 );
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		gsName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( gsName, "OpenOffice" )){
			gsVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
			if(gsVer){
				path = registry_get_sz( key: key + item, item: "InstallLocation" );
				if(!path){
					path = "Could not find the install location from registry";
				}
				set_kb_item( name: "OpenOffice/Win/Ver", value: gsVer );
				cpe = build_cpe( value: gsVer, exp: "^([0-9.]+)", base: "cpe:/a:openoffice:openoffice.org:" );
				if(isnull( cpe )){
					cpe = "cpe:/a:openoffice:openoffice.org";
				}
				if(ContainsString( osArch, "x64" ) && !ContainsString( key, "Wow6432Node" )){
					set_kb_item( name: "OpenOffice64/Win/Ver", value: gsVer );
					cpe = build_cpe( value: gsVer, exp: "^([0-9.]+)", base: "cpe:/a:openoffice:openoffice.org:x64:" );
					if(isnull( cpe )){
						cpe = "cpe:/a:openoffice:openoffice.org:x64";
					}
				}
				register_product( cpe: cpe, location: path );
				log_message( data: build_detection_report( app: "OpenOffice", version: gsVer, install: path, cpe: cpe, concluded: gsVer ) );
			}
		}
	}
}

