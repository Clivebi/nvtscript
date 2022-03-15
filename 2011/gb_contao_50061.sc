if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103352" );
	script_bugtraq_id( 50061 );
	script_cve_id( "CVE-2011-4335" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_name( "Contao CMS Cross-Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/50061" );
	script_xref( name: "URL", value: "http://dev.contao.org/projects/typolight/repository/revisions/1041" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/520046" );
	script_xref( name: "URL", value: "http://www.rul3z.de/advisories/SSCHADV2011-025.txt" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-12-02 11:09:47 +0100 (Fri, 02 Dec 2011)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Vendor updates are available. Please see the references for details." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Contao is prone to a cross-site scripting vulnerability because it
  fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site. This may allow the attacker
  to steal cookie-based authentication credentials and to launch other attacks." );
	script_tag( name: "affected", value: "Contao 2.10.1 is vulnerable. Other versions may also be affected." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
vt_strings = get_vt_strings();
for dir in nasl_make_list_unique( "/contao", "/cms", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	buf = http_get_cache( item: dir + "/", port: port );
	if(!buf || !IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) || ( !ContainsString( buf, "teachers.html" ) && !ContainsString( buf, "academy.html" ) )){
		continue;
	}
	url = NASLString( dir, "/index.php/teachers.html?\"/><script>alert(/", vt_strings["lowercase"], "/)</script>" );
	if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\(/" + vt_strings["lowercase"] + "/\\)</script>", extra_check: "This website is powered by Contao", check_header: TRUE )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

