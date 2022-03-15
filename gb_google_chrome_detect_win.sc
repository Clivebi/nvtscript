if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800120" );
	script_version( "2020-07-03T04:20:43+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-07-03 04:20:43 +0000 (Fri, 03 Jul 2020)" );
	script_tag( name: "creation_date", value: "2008-10-31 15:07:51 +0100 (Fri, 31 Oct 2008)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Google Chrome Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of Google Chrome on Windows.

The script logs in via smb, searches for Google Chrome in the registry and gets
the version from registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
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
if( ContainsString( osArch, "x86" ) ){
	key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
}
else {
	if(ContainsString( osArch, "x64" )){
		key = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
	}
}
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	appName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(appName == "Google Chrome"){
		chromeVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(chromeVer){
			chromePath = registry_get_sz( key: key + item, item: "InstallLocation" );
			set_kb_item( name: "GoogleChrome/Win/Ver", value: chromeVer );
			cpe = build_cpe( value: chromeVer, exp: "^([0-9.]+)", base: "cpe:/a:google:chrome:" );
			if(isnull( cpe )){
				cpe = "cpe:/a:google:chrome";
			}
			set_kb_item( name: "GoogleChrome/Win/InstallLocations", value: tolower( chromePath ) );
			register_product( cpe: cpe, location: chromePath );
			log_message( data: build_detection_report( app: "Google Chrome", version: chromeVer, install: chromePath, cpe: cpe, concluded: chromeVer ) );
		}
	}
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
enumKeys = registry_enum_keys( key: key );
for key in enumKeys {
	chromeVer = registry_get_sz( key: key + "\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Google Chrome", item: "Version", type: "HKU" );
	if(chromeVer){
		chromePath = registry_get_sz( key: key + "\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Google Chrome", item: "InstallLocation", type: "HKU" );
		set_kb_item( name: "GoogleChrome/Win/Ver", value: chromeVer );
		cpe = build_cpe( value: chromeVer, exp: "^([0-9.]+)", base: "cpe:/a:google:chrome:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:google:chrome";
		}
		set_kb_item( name: "GoogleChrome/Win/InstallLocations", value: tolower( chromePath ) );
		register_product( cpe: cpe, location: chromePath );
		log_message( data: build_detection_report( app: "Google Chrome", version: chromeVer, install: chromePath, cpe: cpe, concluded: chromeVer ) );
	}
}

