if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814314" );
	script_version( "$Revision: 11927 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-16 14:17:30 +0200 (Tue, 16 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2018-10-15 12:44:20 +0530 (Mon, 15 Oct 2018)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Adobe Framemaker Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of Adobe Framemaker
  on Windows.

  The script logs in via smb, searches for Adobe Framemaker and gets the
  version from registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
if(!registry_key_exists( key: "SOFTWARE\\Adobe\\FrameMaker" ) && !registry_key_exists( key: "SOFTWARE\\Wow6432Node\\Adobe\\FrameMaker" )){
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
for item in registry_enum_keys( key: key ) {
	appName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(eregmatch( pattern: "Adobe FrameMaker [0-9].*", string: appName )){
		framePath = registry_get_sz( key: key + item, item: "InstallLocation" );
		if(framePath){
			framePath = "Could not find the install location from registry.";
		}
		frameVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(frameVer){
			set_kb_item( name: "AdobeFrameMaker/Win/Ver", value: frameVer );
			cpe = build_cpe( value: frameVer, exp: "^([0-9.]+)", base: "cpe:/a:adobe:framemaker:" );
			if(isnull( cpe )){
				cpe = "cpe:/a:adobe:framemaker";
			}
			register_product( cpe: cpe, location: framePath );
			log_message( data: build_detection_report( app: "Adobe FrameMaker", version: frameVer, install: framePath, cpe: cpe, concluded: frameVer ) );
		}
	}
}

