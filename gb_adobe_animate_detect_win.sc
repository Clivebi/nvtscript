if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809767" );
	script_version( "2019-07-31T09:47:07+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-31 09:47:07 +0000 (Wed, 31 Jul 2019)" );
	script_tag( name: "creation_date", value: "2016-12-19 15:38:50 +0530 (Mon, 19 Dec 2016)" );
	script_name( "Adobe Animate Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of
  Adobe Animate.

  The script logs in via smb, searches for 'Adobe Animate' in the registry,
  fetches install path and version information either from registry or file." );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
if(!registry_key_exists( key: "SOFTWARE\\Adobe\\Animate" )){
	exit( 0 );
}
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ){
	key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
}
else {
	if(ContainsString( os_arch, "x64" )){
		key = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
	}
}
for item in registry_enum_keys( key: key ) {
	appName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( appName, "Adobe Animate" )){
		appPath = registry_get_sz( key: key + item, item: "DisplayIcon" );
		if( appPath ){
			appPath = appPath - "Setup.ico";
			appVer = fetch_file_version( sysPath: appPath, file_name: "Animate.exe" );
		}
		else {
			appVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
			appPath = "Unknown";
		}
		if(!appVer){
			exit( 0 );
		}
		set_kb_item( name: "Adobe/Animate/Win/Ver", value: appVer );
		cpe = build_cpe( value: appVer, exp: "^([0-9.]+)", base: "cpe:/a:adobe:animate:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:adobe:animate";
		}
		register_product( cpe: cpe, location: appPath );
		log_message( data: build_detection_report( app: "Adobe Animate", version: appVer, install: appPath, cpe: cpe, concluded: appVer ) );
		exit( 0 );
	}
}
exit( 0 );

