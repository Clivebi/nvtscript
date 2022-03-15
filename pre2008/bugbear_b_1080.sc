if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11733" );
	script_version( "2020-09-30T09:30:12+0000" );
	script_tag( name: "last_modification", value: "2020-09-30 09:30:12 +0000 (Wed, 30 Sep 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Bugbear.B worm" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2003 Tenable Network Security" );
	script_family( "Malware" );
	script_require_ports( 1080 );
	script_dependencies( "find_service.sc" );
	script_xref( name: "URL", value: "http://www.symantec.com/avcenter/venc/data/w32.bugbear.b@mm.removal.tool.html" );
	script_tag( name: "solution", value: "- Use an Anti-Virus package to remove it.

  - Close your Windows shares

  - See the references for a removal tool." );
	script_tag( name: "summary", value: "BugBear.B backdoor is listening on this port." );
	script_tag( name: "impact", value: "An attacker may connect to it to retrieve secret
  information, e.g. passwords or credit card numbers." );
	script_tag( name: "insight", value: "The BugBear.B worm includes a key logger and can stop
  antivirus or personal firewall software. It propagates itself through email and open
  Windows shares." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("host_details.inc.sc");
require("misc_func.inc.sc");
port = 1080;
if(!get_port_state( port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
send( socket: soc, data: "p" );
r = recv( socket: soc, length: 308 );
close( soc );
if(!strlen( r )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
send( socket: soc, data: "x" );
r2 = recv( socket: soc, length: 308 );
if(strlen( r2 )){
	exit( 0 );
}
close( soc );
if(strlen( r ) > 10){
	security_message( port: port );
	exit( 0 );
}

