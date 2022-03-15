if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11727" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2002-0273" );
	script_bugtraq_id( 4093 );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "CWmail.exe vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2003 John Lampe" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Host/runs_windows" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://marc.info/?l=bugtraq&m=101362100602008&w=2" );
	script_tag( name: "impact", value: "An attacker may make use of this file to gain access to
  confidential data or escalate their privileges on the Web server." );
	script_tag( name: "solution", value: "The vendor has provided a patch to fix this issue.
  Please see the references for more info." );
	script_tag( name: "summary", value: "The CWMail.exe exists on this webserver.
  Some versions of this file are vulnerable to remote exploit." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/cwmail.exe";
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(egrep( pattern: ".*CWMail 2\\.[0-7]\\..*", string: res )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

