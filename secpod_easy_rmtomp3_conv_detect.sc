if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900632" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-04-30 06:40:16 +0200 (Thu, 30 Apr 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Easy RmtoMp3 Converter Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "The script detects the installed Easy RmtoMp3 Converter application." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "Easy RmtoMp3 Converter Version Detection";
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	rmtomp3Name = registry_get_sz( item: "DisplayName", key: key + item );
	if(IsMatchRegexp( rmtomp3Name, "Easy RM to MP3 Converter" )){
		rmtomp3Ver = eregmatch( pattern: " ([0-9.]+)", string: rmtomp3Name );
		if(rmtomp3Ver[1] != NULL){
			set_kb_item( name: "EasyRmtoMp3/Conv/Ver", value: rmtomp3Ver[1] );
			log_message( data: "Easy RmtoMp3 Converter version " + rmtomp3Ver[1] + " was detected on the host" );
			cpe = build_cpe( value: rmtomp3Ver[1], exp: "^([0-9.]+([a-z0-9]+)?)", base: "cpe:/a:mini-stream:easy_rm-mp3_converter:" );
			if(!isnull( cpe )){
				register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
			}
		}
	}
}

