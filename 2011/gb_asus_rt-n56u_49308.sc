if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103228" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2011-4497" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-08-26 14:51:18 +0200 (Fri, 26 Aug 2011)" );
	script_bugtraq_id( 49308 );
	script_tag( name: "cvss_base", value: "3.3" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "ASUS RT-N56U Wireless Router 'QIS_wizard.htm' Password Information Disclosure Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/49308" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/200814" );
	script_xref( name: "URL", value: "http://www.asus.com/Networks/Wireless_Routers/RTN56U/" );
	script_xref( name: "URL", value: "http://www.asus.com/" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "RT-N56U/banner" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "ASUS RT-N56U wireless router is prone to an information-disclosure
vulnerability that exposes sensitive information.

Successful exploits will allow unauthenticated attackers to obtain
sensitive information of the device such as administrative password,
which may aid in further attacks.

ASUS RT-N56U firmware version 1.0.1.4 is vulnerable." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "Basic realm=\"RT-N56U\"" )){
	exit( 0 );
}
url = NASLString( "/QIS_wizard.htm?flag=detect." );
if(http_vuln_check( port: port, url: url, pattern: "<title>ASUS Wireless Router RT-N56U - Quickly Internet Setup" )){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

