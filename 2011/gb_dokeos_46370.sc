CPE = "cpe:/a:dokeos:dokeos";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103075" );
	script_version( "2021-08-11T10:41:15+0000" );
	script_bugtraq_id( 46370 );
	script_tag( name: "last_modification", value: "2021-08-11 10:41:15 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "creation_date", value: "2011-02-15 13:44:44 +0100 (Tue, 15 Feb 2011)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Dokeos <= 1.8.6.2 'style' Parameter XSS Vulnerability" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/46370" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "gb_dokeos_http_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "dokeos/http/detected" );
	script_tag( name: "summary", value: "Dokeos is prone to a cross-site scripting (XSS) vulnerability
  because it fails to properly sanitize user-supplied input." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "impact", value: "An attacker may leverage this issue to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site. This may let the
  attacker steal cookie-based authentication credentials and launch other attacks." );
	script_tag( name: "affected", value: "Dokeos 1.8.6.2 is vulnerable. Other versions may also be
  affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/main/inc/latex.php?code=\"style=\"top:0;position:absolute;width:9999px;height:9999px;\"onmouseover%3d\"alert(" + "'vt-xss-test'" + ")\"";
if(http_vuln_check( port: port, url: url, pattern: "onmouseover=.alert\\('vt-xss-test'\\)", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

