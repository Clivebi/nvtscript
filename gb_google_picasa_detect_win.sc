if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801769" );
	script_version( "2019-07-31T09:47:07+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-31 09:47:07 +0000 (Wed, 31 Jul 2019)" );
	script_tag( name: "creation_date", value: "2011-04-11 14:40:00 +0200 (Mon, 11 Apr 2011)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Google Picasa Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  Google Picasa on Windows.

  The script logs in via smb, searches for Picasa in the registry, gets the
  Picasa installation path from registry and fetches version from
  'moviethumb.exe' file." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("cpe.inc.sc");
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("host_details.inc.sc");
osArch = get_kb_item( "SMB/Windows/Arch" );
if(!osArch){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\Google\\Picasa" ) && !registry_key_exists( key: "SOFTWARE\\Wow6432Node\\Google\\Picasa" )){
	exit( 0 );
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
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		picName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( picName, "Picasa" )){
			picPath = registry_get_sz( key: key + item, item: "UninstallString" );
			if(!isnull( picPath )){
				picPath = ereg_replace( pattern: "\"", replace: "", string: picPath );
				picPath = picPath - "\\Uninstall.exe";
				picVer = fetch_file_version( sysPath: picPath, file_name: "moviethumb.exe" );
				if(picVer){
					set_kb_item( name: "Google/Picasa/Win/Ver", value: picVer );
					cpe = build_cpe( value: picVer, exp: "^([0-9.]+)", base: "cpe:/a:google:picasa:" );
					if(isnull( cpe )){
						cpe = "cpe:/a:google:picasa";
					}
					if(ContainsString( osArch, "x64" ) && !ContainsString( key, "Wow6432Node" )){
						set_kb_item( name: "Google/Picasa64/Win/Ver", value: picVer );
						cpe = build_cpe( value: picVer, exp: "^([0-9.]+)", base: "cpe:/a:google:picasa:x64:" );
						if(isnull( cpe )){
							cpe = "cpe:/a:google:picasa:x64";
						}
					}
					register_product( cpe: cpe, location: picPath );
					log_message( data: build_detection_report( app: "Google Picasa", version: picVer, install: picPath, cpe: cpe, concluded: picVer ) );
					exit( 0 );
				}
			}
		}
	}
}

