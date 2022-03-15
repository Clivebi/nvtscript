if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901188" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-02-28 11:12:07 +0100 (Mon, 28 Feb 2011)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Hex-Rays IDA Pro Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script finds the installed Hex-Rays IDA Pro version." );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	name = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( name, "IDA Pro" )){
		path = registry_get_sz( key: key + item, item: "DisplayIcon" );
		break;
	}
}
if(path){
	share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: path );
	file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: path );
	idaVer = GetVer( share: share, file: file );
	if(!idaVer){
		exit( 0 );
	}
	set_kb_item( name: "IDA/Pro/Ver", value: idaVer );
	set_kb_item( name: "ida/pro/detected", value: TRUE );
	cpe = build_cpe( value: idaVer, exp: "^([0-9.]+)", base: "cpe:/a:hex-rays:ida:" );
	if(!cpe){
		cpe = "cpe:/a:hex-rays:ida";
	}
	register_product( cpe: cpe, location: path, port: 0, service: "smb-login" );
	log_message( data: build_detection_report( app: "Hex-Rays IDA Pro", version: idaVer, install: path, cpe: cpe, concluded: idaVer ) );
}

