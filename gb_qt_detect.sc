if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801234" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2019-11-05T16:13:01+0000" );
	script_tag( name: "last_modification", value: "2019-11-05 16:13:01 +0000 (Tue, 05 Nov 2019)" );
	script_tag( name: "creation_date", value: "2010-07-26 16:14:51 +0200 (Mon, 26 Jul 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Qt Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (c) 2010 Greenbone Networks GmbH" );
	script_family( "Service detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script finds the installed Qt version." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\Trolltech\\" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	name = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( name, "Qt OpenSource" )){
		ver = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(ver != NULL){
			set_kb_item( name: "Qt/Ver", value: ver );
			log_message( data: "Qt OpenSource version " + ver + " was detected on the host" );
		}
	}
}

