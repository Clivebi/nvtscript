if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103412" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_bugtraq_id( 51916 );
	script_cve_id( "CVE-2011-4448", "CVE-2012-0993", "CVE-2012-0995" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Zenphoto Multiple Security Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/51916" );
	script_xref( name: "URL", value: "http://www.zenphoto.org/news/zenphoto-1.4.2.1" );
	script_xref( name: "URL", value: "http://www.zenphoto.org/" );
	script_xref( name: "URL", value: "https://www.htbridge.ch/advisory/HTB23070" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-02-09 12:57:10 +0100 (Thu, 09 Feb 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "The vendor released updates to address these issues. Please see the
references for more information." );
	script_tag( name: "summary", value: "Zenphoto is prone to multiple cross-site scripting vulnerabilities, an
SQL-injection vulnerability, and a PHP code-injection vulnerability." );
	script_tag( name: "impact", value: "An attacker can exploit the cross-site scripting issues to execute
arbitrary script code in the browser of an unsuspecting user in the
context of the affected site. This may allow the attacker to steal cookie-
based authentication credentials. The PHP code injection can be
exploited to inject and execute arbitrary malicious PHP code in the
context of the webserver process.

An attacker may be able to modify the logic of SQL queries. A
successful exploit may allow the attacker to compromise the
software, retrieve information, or modify data, other consequences
are possible as well." );
	script_tag( name: "affected", value: "ZENphoto 1.4.2 is vulnerable, other versions may also be affected" );
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
for dir in nasl_make_list_unique( "/zenphoto", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/zp-core/admin.php?a=&quot;&gt;&lt;script&gt;alert(/xss-test/)&lt;/script&gt;";
	if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\(/xss-test/\\)</script>", check_header: TRUE, extra_check: "zen-logo.png" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

