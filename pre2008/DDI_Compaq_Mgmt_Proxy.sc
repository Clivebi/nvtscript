CPE = "cpe:/a:hp:http_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10963" );
	script_version( "2020-02-03T15:12:40+0000" );
	script_tag( name: "last_modification", value: "2020-02-03 15:12:40 +0000 (Mon, 03 Feb 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2001-0374" );
	script_name( "Compaq Web Based Management Agent Proxy Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2002 Digital Defense Inc." );
	script_family( "Web application abuses" );
	script_dependencies( "compaq_wbem_detect.sc" );
	script_require_ports( "Services/www", 2301 );
	script_mandatory_keys( "compaq/http_server/detected" );
	script_xref( name: "URL", value: "http://www.compaq.com/products/servers/management/SSRT0758.html" );
	script_tag( name: "solution", value: "Due to the information leak associated with this service,
  we recommend that you disable the Compaq Management Agent or filter access to
  TCP ports 2301 and 280.

  If this service is required, installing the appropriate upgrade from Compaq
  will fix this issue. The software update for the operating system and hardware
  can be found via Compaq's support download page.

  For more information, please see the referenced vendor advisory." );
	script_tag( name: "summary", value: "This host is running the Compaq Web Management Agent.
  This service can be used as a HTTP proxy. An attacker can use this
  to bypass firewall rules or hide the source of web-based attacks." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_active" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
req = NASLString( "GET http://127.0.0.1:2301/ HTTP/1.0\\r\\n\\r\\n" );
res = http_keepalive_send_recv( port: port, data: req );
if(ContainsString( res, "Compaq WBEM Device Home" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

