if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103498" );
	script_bugtraq_id( 53493 );
	script_version( "2019-09-06T14:17:49+0000" );
	script_name( "NEC Enterprise Server Backdoor Unauthorized Access Vulnerability" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-09-06 14:17:49 +0000 (Fri, 06 Sep 2019)" );
	script_tag( name: "creation_date", value: "2012-06-21 10:41:21 +0200 (Thu, 21 Jun 2012)" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_copyright( "This script is Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "gb_default_credentials_options.sc" );
	script_require_ports( 5001 );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/53493" );
	script_tag( name: "summary", value: "NEC Enterprise Server is prone to an unauthorized-access vulnerability
  due to a backdoor in all versions of the application." );
	script_tag( name: "impact", value: "Attackers can exploit this issue to gain unauthorized access to the
  affected application. This may aid in further attacks." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by
  another one." );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("telnet_func.inc.sc");
port = 5001;
if(!get_port_state( port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
r = telnet_negotiate( socket: soc );
if(!ContainsString( r, "Integrated Service Processor" )){
	exit( 0 );
}
send( socket: soc, data: "spfw\n" );
recv = recv( socket: soc, length: 512 );
if(!ContainsString( recv, "iSP password" )){
	exit( 0 );
}
send( socket: soc, data: "nec\n" );
recv = recv( socket: soc, length: 512 );
close( soc );
if(ContainsString( recv, "Welcome to Integrated Service Processor" ) && ContainsString( recv, "iSP FW version" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

