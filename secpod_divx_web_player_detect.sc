if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900534" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "DivX Web Player Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script detects the version of DivX Web Player." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "DivX Web Player Version Detection";
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\DivXNetworks" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	divxName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( divxName, "DivX Web" )){
		path = registry_get_sz( key: key + item, item: "DisplayIcon" );
		if(path == NULL){
			exit( 0 );
		}
		break;
	}
}
path = path - ",0";
share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: path );
file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: path );
divVer = GetVer( file: file, share: share );
if(divVer != NULL){
	set_kb_item( name: "DivX/Web/Player/Ver", value: divVer );
	log_message( data: "DivX Web Player version " + divVer + " running at location " + path + " was detected on the host" );
	cpe = build_cpe( value: divVer, exp: "^([0-9.]+)", base: "cpe:/a:divx:divx_web_player:" );
	if(!isnull( cpe )){
		register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
	}
}

