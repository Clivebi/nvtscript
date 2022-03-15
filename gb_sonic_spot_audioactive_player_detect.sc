if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800571" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2019-11-05T16:13:01+0000" );
	script_tag( name: "last_modification", value: "2019-11-05 16:13:01 +0000 (Tue, 05 Nov 2019)" );
	script_tag( name: "creation_date", value: "2009-06-09 08:37:33 +0200 (Tue, 09 Jun 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Sonic Spot Audioactive Player Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "summary", value: "This script detects the version of Sonic Spot Audioactive Player." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "Sonic Spot Audioactive Player Version Detection";
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
key = "SOFTWARE\\Telos Systems\\Audioactive Player";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	audioactiveVer = eregmatch( pattern: "[0-9.]+[a-z]?", string: item );
	if(audioactiveVer != NULL){
		set_kb_item( name: "SonicSpot/Audoiactive/Player/Ver", value: audioactiveVer[0] );
		register_and_report_cpe( app: "Sonic Spot Audioactive Player", ver: audioactiveVer[0], base: "cpe:/a:sonicspot:audioactive_player:", expr: "^([0-9.]+([a-z0-9]+)?)" );
		exit( 0 );
	}
}

