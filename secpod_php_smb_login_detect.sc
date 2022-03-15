if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902435" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-06-02 11:54:09 +0200 (Thu, 02 Jun 2011)" );
	script_name( "PHP Detection (Windows SMB Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "SMB login-based detection of PHP." );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
require("secpod_smb_func.inc.sc");
key = "SOFTWARE\\PHP\\";
if(!registry_key_exists( key: key )){
	key = "SOFTWARE\\Wow6432Node\\PHP\\";
	if(!registry_key_exists( key: key )){
		exit( 0 );
	}
}
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ) {
	key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
}
else {
	if(ContainsString( os_arch, "x64" )){
		key = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
	}
}
phpVer = registry_get_sz( key: key, item: "version" );
phpPath = registry_get_sz( key: key, item: "InstallDir" );
if(!phpPath){
	phpPath = "Could not find the install location from registry";
}
if(!phpVer){
	if(!registry_key_exists( key: key )){
		exit( 0 );
	}
	for item in registry_enum_keys( key: key ) {
		phpName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( phpName, "PHP" )){
			phpVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		}
	}
}
if(!isnull( phpVer )){
	if(ContainsString( phpVer, "RC" )){
		version = eregmatch( string: phpVer, pattern: "([0-9.]+)(RC([0-9]+))?" );
		version[2] = tolower( version[2] );
		ver = version[1] + version[2];
		phpVer = version[1] + "." + version[2];
	}
	set_kb_item( name: "php/detected", value: TRUE );
	if( ver ) {
		cpe = build_cpe( value: ver, exp: "([0-9.]+)(RC([0-9]+))?", base: "cpe:/a:php:php:" );
	}
	else {
		cpe = build_cpe( value: phpVer, exp: "^([0-9.]+)", base: "cpe:/a:php:php:" );
	}
	if(!cpe){
		cpe = "cpe:/a:php:php";
	}
	register_product( cpe: cpe, location: phpPath, port: 0, service: "ssh-login" );
	log_message( data: build_detection_report( app: "PHP", version: phpVer, install: phpPath, cpe: cpe, concluded: version[0] ), port: 0 );
}
exit( 0 );

