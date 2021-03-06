if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902798" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-02-28 10:56:55 +0530 (Tue, 28 Feb 2012)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Microsoft SMB Signing Enabled and Not Required At Server" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "cifs445.sc", "netbios_name_get.sc", "logins.sc" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "Checks if SMB Signing is enabled and not required
  at the remote SMB server." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("smb_nt.inc.sc");
name = kb_smb_name();
port = kb_smb_transport();
if(!soc = open_sock_tcp( port )){
	exit( 0 );
}
response = smb_session_request( soc: soc, remote: name );
if(!response){
	close( soc );
	exit( 0 );
}
prot = smb_neg_prot( soc: soc );
close( soc );
if(prot && ord( prot[39] ) == 7){
	log_message( port: port, data: "SMB Signing is enabled but not required at the server." );
	exit( 0 );
}
exit( 99 );

