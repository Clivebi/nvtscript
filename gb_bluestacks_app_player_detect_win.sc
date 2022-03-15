if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809785" );
	script_version( "2021-01-15T07:13:31+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-01-15 07:13:31 +0000 (Fri, 15 Jan 2021)" );
	script_tag( name: "creation_date", value: "2017-01-24 15:30:35 +0530 (Tue, 24 Jan 2017)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "BlueStacks App Player Detection (Windows SMB Login)" );
	script_tag( name: "summary", value: "SMB login-based detection of BlueStacks App Player." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\BlueStacks" )){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ) {
	key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\BlueStacks\\";
}
else {
	if(ContainsString( os_arch, "x64" )){
		key = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\BlueStacks\\";
	}
}
if(!key){
	exit( 0 );
}
blName = registry_get_sz( key: key, item: "DisplayName" );
if(ContainsString( blName, "BlueStacks App Player" )){
	vers = "unknown";
	path = "unknown";
	blVer = registry_get_sz( key: key, item: "DisplayVersion" );
	if(blVer){
		set_kb_item( name: "Bluestacks/App/Player/Win/Ver", value: blVer );
		vers = blVer;
	}
	blPath = registry_get_sz( key: key, item: "DisplayIcon" );
	if(blPath){
		path = blPath - "BlueStacks.ico";
	}
	cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:bluestacks:bluestacks:" );
	if(!cpe){
		cpe = "cpe:/a:bluestacks:bluestacks";
	}
	register_product( cpe: cpe, location: path, port: 0, service: "smb-login" );
	log_message( data: build_detection_report( app: "BlueStacks App Player", version: vers, install: path, cpe: cpe, concluded: blVer ) );
}
exit( 0 );

