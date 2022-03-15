CPE = "cpe:/a:weberp:weberp";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103343" );
	script_version( "2021-02-03T10:09:03+0000" );
	script_tag( name: "last_modification", value: "2021-02-03 10:09:03 +0000 (Wed, 03 Feb 2021)" );
	script_tag( name: "creation_date", value: "2011-11-21 08:36:41 +0100 (Mon, 21 Nov 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_bugtraq_id( 50713 );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "webERP Information Disclosure, SQL Injection, and Cross Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/50713" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/520561" );
	script_xref( name: "URL", value: "https://www.htbridge.ch/advisory/multiple_vulnerabilities_in_weberp.html" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "gb_weberp_http_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "weberp/detected" );
	script_tag( name: "solution", value: "Vendor updates are available. Please see the references for more
information." );
	script_tag( name: "summary", value: "webERP is prone to information-disclosure, SQL-injection, and cross-
site scripting vulnerabilities because it fails to sufficiently
sanitize user-supplied input.

An attacker may exploit the information-disclosure issue to gain
access to sensitive information that may lead to further attacks.

An attacker may exploit the SQL-injection issue to compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database.

An attacker may leverage the cross-site scripting issue to execute
arbitrary script code in the browser of an unsuspecting user in the
context of the affected site. This may allow the attacker to steal cookie-
based authentication credentials and launch other attacks.

webERP 4.0.5 is vulnerable. Prior versions may also be affected." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
vt_strings = get_vt_strings();
url = NASLString( dir, "/AccountSections.php/%22%3E%3Cscript%3Ealert(/", vt_strings["lowercase"], "/);%3C/script%3E" );
if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\(/" + vt_strings["lowercase"] + "/\\);</script>", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

