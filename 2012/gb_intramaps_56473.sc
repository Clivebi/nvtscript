if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103605" );
	script_bugtraq_id( 56473 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_name( "Intramaps Multiple Security Vulnerabilities" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-11-12 10:40:31 +0100 (Mon, 12 Nov 2012)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/56473" );
	script_xref( name: "URL", value: "http://www.stratsec.net/Research/Advisories/Intramaps-Multiple-Vulnerabilities-%28SS-2012-007%29" );
	script_tag( name: "solution", value: "Reportedly these issues are fixed. Please contact the vendor for more
  information." );
	script_tag( name: "summary", value: "Intramaps is prone to multiple security vulnerabilities including:

  1. Multiple cross-site scripting vulnerabilities

  2. Multiple SQL-injection vulnerabilities

  3. An information-disclosure vulnerability

  4. A cross-site request-forgery vulnerability

  5. An XQuery-injection vulnerability" );
	script_tag( name: "impact", value: "An attacker can exploit these vulnerabilities to execute arbitrary
  script code in the browser of an unsuspecting user in the context of
  the affected site, steal cookie-based authentication credentials,
  access or modify data, exploit vulnerabilities in the underlying
  database, disclose sensitive information, and perform unauthorized
  actions. Other attacks are also possible." );
	script_tag( name: "affected", value: "Intramaps 7.0.128 Rev 318 is vulnerable, other versions may also
  be affected." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
subdirs = make_list( "/applicationengine",
	 "/ApplicationEngine" );
for dir in nasl_make_list_unique( "/IntraMaps", "/intramaps75", "/IntraMaps70", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	for subdir in subdirs {
		url = dir + subdir + "/";
		if(http_vuln_check( port: port, url: url, pattern: "<title>IntraMaps" )){
			url = dir + subdir + "/Application.aspx?project=NAME</script><script>alert('xss-test')</script>";
			if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\('xss-test'\\)</script>", check_header: TRUE )){
				report = http_report_vuln_url( port: port, url: url );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

