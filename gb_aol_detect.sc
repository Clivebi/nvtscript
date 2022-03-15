if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801025" );
	script_version( "2019-07-31T09:47:07+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-31 09:47:07 +0000 (Wed, 31 Jul 2019)" );
	script_tag( name: "creation_date", value: "2009-10-22 15:34:45 +0200 (Thu, 22 Oct 2009)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "America Online (AOL) Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of America Online (AOL) on Windows.

The script logs in via smb, searches for America Online in the registry
and gets the install location and extract version from the file." );
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
key = "SOFTWARE\\America Online\\AOL";
if(!registry_key_exists( key: key )){
	key = "SOFTWARE\\Wow6432Node\\America Online\\AOL";
	if(!registry_key_exists( key: key )){
		exit( 0 );
	}
}
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ){
	key = "SOFTWARE\\America Online\\AOL\\";
}
else {
	if(ContainsString( os_arch, "x64" )){
		key = "SOFTWARE\\Wow6432Node\\America Online\\AOL\\";
	}
}
appPath = registry_get_sz( key: key + "CurrentVersion", item: "AppPath" );
if(appPath != NULL){
	version = fetch_file_version( sysPath: appPath, file_name: "aol.exe" );
	if(version != NULL){
		set_kb_item( name: "AOL/Ver", value: version );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:aol:internet_software:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:aol:internet_software";
		}
		register_product( cpe: cpe, location: appPath );
		log_message( data: build_detection_report( app: "America Online (AOL)", version: version, install: appPath, cpe: cpe, concluded: version ) );
	}
}

