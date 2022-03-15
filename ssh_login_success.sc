if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108540" );
	script_version( "$Revision: 13248 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-01-23 16:35:02 +0100 (Wed, 23 Jan 2019) $" );
	script_tag( name: "creation_date", value: "2019-01-23 15:50:49 +0100 (Wed, 23 Jan 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "SSH Login Successful For Authenticated Checks" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "ssh_authorization.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_tag( name: "summary", value: "It was possible to login using the provided SSH
  credentials. Hence authenticated checks are enabled." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("ssh_func.inc.sc");
port = get_kb_item( "login/SSH/success/port" );
if(!port){
	port = kb_ssh_transport();
}
log_message( port: port );
exit( 0 );

