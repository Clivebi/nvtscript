CPE = "cpe:/a:apachefriends:xampp";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100885" );
	script_version( "2021-06-24T02:07:35+0000" );
	script_tag( name: "last_modification", value: "2021-06-24 02:07:35 +0000 (Thu, 24 Jun 2021)" );
	script_tag( name: "creation_date", value: "2010-11-02 13:46:58 +0100 (Tue, 02 Nov 2010)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "XAMPP XSS and Information Disclosure Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_xampp_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "xampp/detected" );
	script_tag( name: "summary", value: "XAMPP is prone to multiple cross-site scripting vulnerabilities and an
  information disclosure vulnerability because the application fails to
  sufficiently sanitize user-supplied input." );
	script_tag( name: "impact", value: "Attackers can exploit these issues to obtain sensitive information,
  steal cookie-based authentication information, and execute arbitrary
  client-side scripts in the context of the browser." );
	script_tag( name: "affected", value: "XAMPP 1.7.3 is vulnerable, other versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/44579" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: cpe, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/phonebook.php/%22%3E%3Cscript%3Ealert(%27vt-xss-test%27)%3C/script%3E";
if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\('vt-xss-test'\\)</script>", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

