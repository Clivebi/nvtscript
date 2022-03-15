CPE = "cpe:/a:sybase:adaptive_server_enterprise";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.80018" );
	script_version( "2020-05-28T12:19:25+0000" );
	script_tag( name: "last_modification", value: "2020-05-28 12:19:25 +0000 (Thu, 28 May 2020)" );
	script_tag( name: "creation_date", value: "2008-10-24 19:51:47 +0200 (Fri, 24 Oct 2008)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Sybase SQL Blank Password" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2008 Tenable Network Security" );
	script_family( "Databases" );
	script_require_ports( "Services/sybase", 5000 );
	script_dependencies( "gb_sybase_tcp_listen_detect.sc" );
	script_mandatory_keys( "sybase/tcp_listener/detected" );
	script_tag( name: "solution", value: "Either disable this account or set a password for it." );
	script_tag( name: "summary", value: "The remote Sybase SQL server has the default 'sa' account
  enabled without any password." );
	script_tag( name: "impact", value: "An attacker may use this flaw to execute commands against the
  remote host as well as read database content." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("host_details.inc.sc");
require("sybase_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "sybase_tcp_listener" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
sql_packet = make_sql_login_pkt( username: "sa", password: "" );
send( socket: soc, data: sql_packet );
send( socket: soc, data: pkt_lang );
r = recv( socket: soc, length: 255 );
close( soc );
if(strlen( r ) > 10 && ord( r[8] ) == 0xE3){
	version = substr( r, strlen( r ) - 13, strlen( r ) - 10 );
	strver = NULL;
	for(i = 0;i < 4;i++){
		if(strver){
			strver += ".";
		}
		strver += ord( version[i] );
	}
	set_kb_item( name: "sybase/version", value: strver );
	security_message( port: port );
}
exit( 0 );

