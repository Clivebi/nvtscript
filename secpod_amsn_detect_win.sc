if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902044" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-04-29 10:04:32 +0200 (Thu, 29 Apr 2010)" );
	script_name( "aMSN Version Detection (Windows)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script detects the installed version of aMSN." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "aMSN Version Detection (Windows)";
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\AMSN-Pack" )){
	exit( 0 );
}
msnVer = registry_get_sz( key: "SOFTWARE\\Affinix\\AMSN-Pack", item: "Version" );
if(msnVer != NULL){
	set_kb_item( name: "aMSN/Win/Ver", value: msnVer );
	log_message( data: "aMSN version " + msnVer + " was detected on the host" );
	cpe = build_cpe( value: msnVer, exp: "^([0-9.]+)", base: "cpe:/a:amsn:amsn:" );
	if(!isnull( cpe )){
		register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
	}
}

