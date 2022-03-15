if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11415" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 6302, 7019 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2002-1276", "CVE-2002-1341" );
	script_xref( name: "RHSA", value: "RHSA-2003:0042-07" );
	script_name( "SquirrelMail Cross-Site Scripting Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2005 Xue Yong Zhi" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "cross_site_scripting.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade to a newer version of this software" );
	script_tag( name: "summary", value: "The remote host seems to be vulnerable to a security problem in
  SquirrelMail. Its script 'read_body.php' didn't filter out user input for
  'filter_dir' and 'mailbox', making an XSS attack possible." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod", value: "50" );
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
host = http_host_name( dont_add_port: TRUE );
if(http_get_has_generic_xss( port: port, host: host )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/read_body.php" + NASLString( "?mailbox=", "<script>alert(document.cookie)</script>&passed_id=", "<script>alert(document.cookie)</script>&", "startMessage=1&show_more=0" );
	if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\(document\\.cookie\\)</script>", check_header: TRUE )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

