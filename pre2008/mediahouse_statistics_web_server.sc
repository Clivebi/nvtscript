if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10748" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 1568 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2000-0776" );
	script_name( "Mediahouse Statistics Web Server Detect" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2001 SecuriTeam" );
	script_family( "Web Servers" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Statistics_Server/banner" );
	script_tag( name: "solution", value: "Block the web server's port number on your Firewall, and
  upgrade to the latest version if necessary." );
	script_tag( name: "summary", value: "We detected the remote web server as a
  Mediahouse Statistics web server. This web server suffers from a security
  vulnerability that enables attackers to gain sensitive information on the
  current logged events on the public web server (the server being monitored
  by MediaHouse).

  This information includes: who is on (currently surfing users), the user's
  actions, customer's IP addresses, referrer URLs, hidden directories, web
  server usernames and passwords, and more.

  Some versions of the product also suffer from a flaw that allows attackers
  to overflow an internal buffer causing it to execute arbitrary code." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
buf = http_get_remote_headers( port: port );
if(!buf){
	exit( 0 );
}
if(egrep( pattern: "^Server: Statistics Server", string: buf )){
	buf = strstr( buf, "Location: " );
	buf = buf - "Location: ";
	subbuf = strstr( buf, NASLString( "\\n" ) );
	buf = buf - subbuf;
	buf = buf - raw_string( 0x0D );
	soc = http_open_socket( port );
	if(soc){
		req = http_get( item: buf, port: port );
		send( socket: soc, data: req );
		buf = http_recv( socket: soc );
		http_close_socket( soc );
		if(ContainsString( buf, "Statistics Server " )){
			buf = strstr( buf, "<TITLE>Statistics Server " );
			buf = buf - "<TITLE>Statistics Server ";
			subbuf = strstr( buf, "</TITLE>" );
			buf = buf - subbuf;
			buf = buf - "</TITLE>";
			version = buf;
			buf = "Remote host is running Statistics Server version: ";
			buf = buf + version;
			if( ereg( pattern: "(([0-4]\\.[0-9].*)|5\\.0[0-2])", string: version ) ){
				report = NASLString( "According to its version number, the remote MediaHouse\\n", "Statistics Server is vulnerable to a buffer overflow that\\n", "allows anyone to execute arbitrary code as root.\\n\\n", "Solution: Upgrade to version 5.03 or newer" );
				security_message( data: report, port: port );
			}
			else {
				security_message( port: port );
			}
		}
	}
}
exit( 99 );

