if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.101001" );
	script_version( "2019-09-06T14:17:49+0000" );
	script_tag( name: "last_modification", value: "2019-09-06 14:17:49 +0000 (Fri, 06 Sep 2019)" );
	script_tag( name: "creation_date", value: "2009-03-08 15:05:20 +0100 (Sun, 08 Mar 2009)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_bugtraq_id( 7315 );
	script_name( "FileMaker Pro User Password Disclosure Vulnerability" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_copyright( "Christian Eric Edjenguele <christian.edjenguele@owasp.org>" );
	script_family( "General" );
	script_dependencies( "remote-detect-filemaker.sc" );
	script_mandatory_keys( "FileMaker/installed" );
	script_require_ports( 5003 );
	script_tag( name: "summary", value: "The remote Filemaker database server is prone to a User Password Disclosure Vulnerability,
  because it does not properly secure credentials during authentication." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	exit( 0 );
}
if(!get_kb_item( "FileMaker/installed" )){
	exit( 0 );
}
port = 5003;
if(!get_port_state( port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
filemaker_auth_packet = "\\x00\\x04\\x13\\x00";
send( socket: soc, data: filemaker_auth_packet );
reply = recv( socket: soc, length: 3 );
if(reply == "\\x00\\x06\\x14"){
	security_message( port: port, data: "The target host was found to be vulnerable." );
	exit( 0 );
}
exit( 99 );

