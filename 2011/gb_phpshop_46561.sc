if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103093" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-02-28 14:46:59 +0100 (Mon, 28 Feb 2011)" );
	script_bugtraq_id( 46561 );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:P/A:N" );
	script_name( "phpShop 'page' Parameter Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/46561" );
	script_xref( name: "URL", value: "http://sourceforge.net/projects/phpshop/" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "phpshop_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpshop/detected" );
	script_tag( name: "summary", value: "phpShop is prone to a cross-site scripting vulnerability because it
  fails to sufficiently sanitize user-supplied data." );
	script_tag( name: "impact", value: "An attacker may leverage this issue to execute arbitrary HTML and
  script code in the browser of an unsuspecting user in the context of
  the affected site. This may allow the attacker to steal cookie-based
  authentication credentials and to launch other attacks." );
	script_tag( name: "affected", value: "phpShop versions 0.8.1 and prior are vulnerable." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(!dir = get_dir_from_kb( port: port, app: "phpshop" )){
	exit( 0 );
}
url = NASLString( dir, "/?page=store/XSS&amp;%26%26\"><script>alert(/vt-xss-test/)</script>%3d1" );
if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\(/vt-xss-test/\\)</script>", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

