if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106091" );
	script_version( "2021-01-18T10:34:23+0000" );
	script_tag( name: "last_modification", value: "2021-01-18 10:34:23 +0000 (Mon, 18 Jan 2021)" );
	script_tag( name: "creation_date", value: "2016-06-03 10:44:56 +0700 (Fri, 03 Jun 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "SMB Login Failed For Authenticated Checks" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "smb_login.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "login/SMB/failed" );
	script_xref( name: "URL", value: "https://docs.greenbone.net/GSM-Manual/gos-20.08/en/scanning.html#requirements-on-target-systems-with-microsoft-windows" );
	script_tag( name: "summary", value: "It was NOT possible to login using the provided SMB
  credentials. Hence authenticated checks are NOT enabled." );
	script_tag( name: "solution", value: "Recheck the SMB credentials and configuration for authenticated checks." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("smb_nt.inc.sc");
port = get_kb_item( "login/SMB/failed/port" );
if(!port){
	port = kb_smb_transport();
}
log_message( port: port );
exit( 0 );

