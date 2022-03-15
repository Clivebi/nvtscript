if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11772" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Generic SMTP overflows" );
	script_category( ACT_DESTRUCTIVE_ATTACK );
	script_copyright( "Copyright (C) 2003 Michel Arboi" );
	script_family( "SMTP problems" );
	script_dependencies( "smtpserver_detect.sc" );
	script_require_ports( "Services/smtp", 25, 465, 587 );
	script_mandatory_keys( "smtp/banner/available" );
	script_tag( name: "solution", value: "Upgrade your MTA or change it." );
	script_tag( name: "summary", value: "The remote SMTP server crashes when it is send a command
  with a too long argument." );
	script_tag( name: "impact", value: "An attacker might use this flaw to kill this service or worse, execute arbitrary code on your server." );
	script_tag( name: "qod_type", value: "remote_active" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("smtp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = smtp_get_port( default: 25 );
if(smtp_get_is_marked_wrapped( port: port )){
	exit( 0 );
}
host = get_host_name();
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
banner = smtp_recv_banner( socket: soc );
if(!banner){
	smtp_close( socket: soc, check_data: banner );
	exit( 0 );
}
cmds = make_list( "HELO",
	 "EHLO",
	 "MAIL FROM:",
	 "RCPT TO:",
	 "ETRN" );
args = make_list( "test.example.org",
	 "test.example.org",
	 strcat( "test@",
	 host ),
	 strcat( "test@[",
	 get_host_ip(),
	 "]" ),
	 "test.example.org" );
n = max_index( cmds );
for(i = 0;i < n;i++){
	send( socket: soc, data: NASLString( cmds[i], " ", str_replace( string: args[i], find: "test", replace: crap( 4095 ) ), "\\r\\n" ) );
	for{
		data = recv_line( socket: soc, length: 32768 );
		
		if( !IsMatchRegexp( data, "^[0-9]{3}[ -]" ) ){
			break;
		}
	}
	for{
		data2 = recv_line( socket: soc, length: 32768, timeout: 1 );
		
		if( !IsMatchRegexp( data2, "^[0-9]{3}[ -]" ) ){
			break;
		}
	}
	if(!data){
		close( soc );
		soc = open_sock_tcp( port );
		if(!soc){
			security_message( port );
			exit( 0 );
		}
		for(j = 0;j <= i;j++){
			send( socket: soc, data: NASLString( cmds[i], " ", args[i], "r\\n" ) );
			data = recv_line( socket: soc, length: 32768 );
		}
	}
}
smtp_close( socket: soc, check_data: data );
exit( 99 );

