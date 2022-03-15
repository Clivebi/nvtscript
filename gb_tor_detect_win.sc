if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800351" );
	script_version( "2019-11-05T16:13:01+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-11-05 16:13:01 +0000 (Tue, 05 Nov 2019)" );
	script_tag( name: "creation_date", value: "2009-02-06 13:48:17 +0100 (Fri, 06 Feb 2009)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Tor Version Detection (Windows)" );
	script_tag( name: "summary", value: "This script detects the installed version of Tor.

  The script logs in via smb, searches for Tor in the registry
  and gets the version from registry or file." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ){
	key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Tor";
}
else {
	if(ContainsString( os_arch, "x64" )){
		key = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Tor";
	}
}
if(!registry_key_exists( key: key )){
	exit( 0 );
}
torName = registry_get_sz( key: key, item: "DisplayName" );
if(ContainsString( torName, "Tor" )){
	torVer = eregmatch( pattern: "Tor ([0-9.]+-?([a-z0-9]+)?)", string: torName );
	torVer = torVer[1];
	torPath = registry_get_sz( key: key, item: "UninstallString" );
	torPath = str_replace( string: torPath, find: "\"", replace: "" );
	torPath = torPath - "Uninstall.exe";
	if(!torVer){
		torVer = fetch_file_version( sysPath: torPath, file_name: "Uninstall.exe" );
		if(!torVer){
			exit( 0 );
		}
	}
	if(torVer){
		set_kb_item( name: "Tor/Win/Ver", value: torVer[1] );
		cpe = build_cpe( value: torVer, exp: "^([0-9.]+-?([a-z0-9]+)?)", base: "cpe:/a:tor:tor:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:tor:tor";
		}
		register_product( cpe: cpe, location: torPath );
		log_message( data: build_detection_report( app: torName, version: torVer, install: torPath, cpe: cpe, concluded: torVer ) );
	}
}

