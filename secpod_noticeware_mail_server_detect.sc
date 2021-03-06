if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900462" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-02-26 05:27:20 +0100 (Thu, 26 Feb 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "NoticeWare Email Server Version Detection" );
	script_family( "Product detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script detects the installed NoticeWare Email Server." );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("smb_nt.inc.sc");
require("smtp_func.inc.sc");
require("secpod_smb_func.inc.sc");
SCRIPT_DESC = "NoticeWare Email Server Version Detection";
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\NoticeWare\\EmailServer" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	name = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( name, "NoticeWare Email Server" )){
		ver = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(ver != NULL){
			set_kb_item( name: "NoticeWare/Mail/Server/Ver", value: ver );
			log_message( data: "NoticeWare Email Server version " + ver + " was detected on the host" );
			cpe = build_cpe( value: ver, exp: "^([0-9.]+)", base: "cpe:/a:noticeware:noticeware_email_server_ng:" );
			if(!isnull( cpe )){
				register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
			}
			exit( 0 );
		}
	}
}

