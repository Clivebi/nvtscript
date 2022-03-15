if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103461" );
	script_bugtraq_id( 52941 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2012-1934" );
	script_name( "Sourcefabric Newscoop Multiple Cross Site Scripting and SQL Injection Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/52941" );
	script_xref( name: "URL", value: "http://dev.sourcefabric.org/browse/CS-4184" );
	script_xref( name: "URL", value: "http://dev.sourcefabric.org/browse/CS-4183" );
	script_xref( name: "URL", value: "http://dev.sourcefabric.org/browse/CS-4182" );
	script_xref( name: "URL", value: "http://www.sourcefabric.org/en/products/newscoop_release/570/Newscoop-352-is-out!.htm" );
	script_xref( name: "URL", value: "http://dev.sourcefabric.org/browse/CS-4181" );
	script_xref( name: "URL", value: "http://www.sourcefabric.org/en/newscoop/latestrelease/1141/Newscoop-355-and-Newscoop-4-RC4-security-releases.htm" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-04-10 10:02:36 +0200 (Tue, 10 Apr 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more details." );
	script_tag( name: "summary", value: "Sourcefabric Newscoop is prone to multiple cross-site scripting and
SQL-injection vulnerabilities because it fails to properly sanitize
user-supplied input before using it in dynamically generated content." );
	script_tag( name: "impact", value: "Exploiting these issues could allow an attacker to steal cookie-
based authentication credentials, compromise the application,
access or modify data, or exploit latent vulnerabilities in the
underlying database." );
	script_tag( name: "affected", value: "Sourcefabric Newscoop 3.5.4 is vulnerable, prior versions may also
be affected." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/newscoop", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/admin/password_check_token.php?f_email=1&token=%22%3E%3Cscript%3Ealert%28/xss-test/%29;%3C/script%3E";
	if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\(/xss-test/\\);</script>", check_header: TRUE, extra_check: "Bad input parameters" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

