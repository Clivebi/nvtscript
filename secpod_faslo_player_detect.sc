if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900253" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-11-23 07:01:19 +0100 (Mon, 23 Nov 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Faslo Player Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script detects the installed version of Faslo player." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "Faslo Player Version Detection";
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\Faslo" )){
	exit( 0 );
}
fpVer = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" + "\\Uninstall\\Faslo", item: "DisplayVersion" );
if(fpVer != NULL){
	set_kb_item( name: "FasloPlayer/Ver", value: fpVer );
	log_message( data: "Faslo Player version " + fpVer + " was detected on the host" );
	cpe = build_cpe( value: fpVer, exp: "^([0-9.]+)", base: "cpe:/a:faslo:faslo_player:" );
	if(!isnull( cpe )){
		register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
	}
}

