if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103619" );
	script_bugtraq_id( 56575 );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Omni-Secure 'dir' Parameter Multiple File Disclosure Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/56575" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-12-07 10:59:11 +0100 (Fri, 07 Dec 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Omni-Secure is prone to multiple file-disclosure vulnerabilities.

  An attacker can exploit these issues to view local files in the
  context of the web server process. This may aid in further attacks.

  Versions Omni-Secure 5, 6 and 7 are vulnerable." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
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
files = make_list( "/browsefiles.php",
	 "/browsefolders.php" );
for dir in nasl_make_list_unique( "/oss7", "/oss6", "/oss5", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	for file in files {
		url = dir + "/lib" + file + "?dir=/etc";
		if(http_vuln_check( port: port, url: url, pattern: "/etc/passwd", extra_check: "/etc/shadow" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

