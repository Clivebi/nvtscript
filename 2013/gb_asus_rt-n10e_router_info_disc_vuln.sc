if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803769" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2013-3610" );
	script_bugtraq_id( 62850 );
	script_tag( name: "cvss_base", value: "6.1" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:C/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-10-10 13:46:03 +0530 (Thu, 10 Oct 2013)" );
	script_name( "ASUS RT-N10E Wireless Router Information Disclosure Vulnerability" );
	script_tag( name: "summary", value: "This host is running ASUS RT-N10E Wireless Router and is prone to information
  disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Send direct HTTP GET request and check it is possible to read the password
  and other information or not." );
	script_tag( name: "solution", value: "Upgrade to ASUS Wireless-N150 Router RT-N10E firmware 2.0.0.25 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "insight", value: "The flaw is due to the device not properly restricting access to the
  '/qis/QIS_finish.htm' page." );
	script_tag( name: "affected", value: "ASUS Wireless-N150 Router RT-N10E firmware versions 2.0.0.24 and earlier." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attacker to disclose certain
  sensitive information." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/55159" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/984366" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "RT-N10E/banner" );
	script_xref( name: "URL", value: "http://www.asus.com/Networking/RTN10E/#support_Download" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8080 );
banner = http_get_remote_headers( port: port );
if(banner && !ContainsString( banner, "WWW-Authenticate: Basic realm=\"RT-N10E\"" )){
	exit( 0 );
}
url = "/qis/QIS_finish.htm";
if(http_vuln_check( port: port, url: url, pattern: "ASUS Wireless Router", extra_check: make_list( "password_item",
	 "account_item",
	 "#wanip_item" ) )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}

