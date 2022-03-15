if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900453" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-02-02 05:02:24 +0100 (Mon, 02 Feb 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Total Video Player Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script detects the installed version of Total Video Player." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "Total Video Player Version Detection";
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\iTinySoft\\Total Video Player" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
entries = registry_enum_keys( key: key );
if(entries == NULL){
	exit( 0 );
}
for item in entries {
	name = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( name, "Total Video Player" )){
		tvpVer = eregmatch( pattern: "Total Video Player ([0-9.]+)", string: name );
		if(tvpVer[1] != NULL){
			set_kb_item( name: "TotalVideo/Player/Ver", value: tvpVer[1] );
			log_message( data: "Total Video Player version " + tvpVer[1] + " was detected on the host" );
			cpe = build_cpe( value: tvpVer[1], exp: "^([0-9.]+?)", base: "cpe:/a:effectmatrix:total_video_player:" );
			if(!isnull( cpe )){
				register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
			}
		}
		exit( 0 );
	}
}

