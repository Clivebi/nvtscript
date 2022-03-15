if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900196" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-01-29 15:16:47 +0100 (Thu, 29 Jan 2009)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Winamp Version Detection" );
	script_tag( name: "summary", value: "Detects the installed version of Winamp.

The script logs in via smb, searches for the installed version of Winamp
in registry and gets the version from registry." );
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
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\winamp.exe";
if(isnull( key )){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\winamp.exe" )){
	exit( 0 );
}
winampPath = registry_get_sz( key: key, item: "Path" );
if(!winampPath){
	exit( 0 );
}
winampVer = fetch_file_version( sysPath: winampPath, file_name: "winamp.exe" );
if(winampVer){
	set_kb_item( name: "Winamp/Version", value: winampVer );
	cpe = build_cpe( value: winampVer, exp: "^([0-9.]+)", base: "cpe:/a:nullsoft:winamp:" );
	if(isnull( cpe )){
		cpe = "cpe:/a:nullsoft:winamp";
	}
	register_product( cpe: cpe, location: winampPath );
	log_message( data: build_detection_report( app: "Winamp", version: winampVer, install: winampPath, cpe: cpe, concluded: winampVer ) );
}

