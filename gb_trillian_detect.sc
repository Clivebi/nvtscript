if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800264" );
	script_version( "2019-07-31T09:47:07+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-31 09:47:07 +0000 (Wed, 31 Jul 2019)" );
	script_tag( name: "creation_date", value: "2009-04-07 07:29:53 +0200 (Tue, 07 Apr 2009)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Trillian Version Detection" );
	script_tag( name: "summary", value: "Detects the installed version of Trillian on Windows.

The script logs in via smb, searches for Trillian in the registry
and gets the version from the file." );
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
if(!registry_key_exists( key: "SOFTWARE\\Clients\\IM\\Trillian" )){
	if(!registry_key_exists( key: "SOFTWARE\\Wow6432Node\\Clients\\IM\\Trillian" )){
		exit( 0 );
	}
}
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ){
	key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Trillian";
}
else {
	if(ContainsString( os_arch, "x64" )){
		key = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Trillian";
	}
}
if(!registry_key_exists( key: key )){
	exit( 0 );
}
exePath = registry_get_sz( key: key, item: "DisplayIcon" );
dllFile = ereg_replace( pattern: "(t|T)rillian.exe", string: exePath, replace: "" );
if(dllFile != NULL){
	triVer = fetch_file_version( sysPath: dllFile, file_name: "toolkit.dll" );
	if(triVer){
		set_kb_item( name: "Trillian/Ver", value: triVer );
		cpe = build_cpe( value: triVer, exp: "^([0-9.]+)", base: "cpe:/a:ceruleanstudios:trillian:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:ceruleanstudios:trillian";
		}
		register_product( cpe: cpe, location: dllFile );
		log_message( data: build_detection_report( app: "Trillian", version: triVer, install: dllFile, cpe: cpe, concluded: triVer ) );
	}
}

