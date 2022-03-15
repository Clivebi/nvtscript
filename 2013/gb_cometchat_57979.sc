if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103669" );
	script_bugtraq_id( 57979 );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:P/A:P" );
	script_name( "CometChat Remote Code Execution and Cross-Site Scripting Vulnerabilities" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-02-26 12:54:40 +0100 (Tue, 26 Feb 2013)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/57979" );
	script_tag( name: "solution", value: "Updates are available. Please see the references or vendor advisory
  for more information." );
	script_tag( name: "summary", value: "CometChat is prone to a cross-site scripting vulnerability and a
  remote code-execution vulnerability because the application fails to sufficiently sanitize user-supplied data." );
	script_tag( name: "impact", value: "An attacker may leverage the cross-site scripting issue to execute
  arbitrary script code in the browser of an unsuspecting user in the context of the affected site.
  This may allow the attacker to steal cookie-based authentication credentials and launch other attacks.

  An attacker can exploit the remote code-execution issue to execute arbitrary code in the context of the
  application. Failed attacks may cause denial-of-service conditions." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
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
for dir in nasl_make_list_unique( "/cometchat", "/chat", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.html";
	buf = http_get_cache( item: url, port: port );
	if(ContainsString( buf, "<title>CometChat" )){
		url = dir + "/modules/chatrooms/chatrooms.php?action=phpinfo";
		if(http_vuln_check( port: port, url: url, pattern: "<title>phpinfo\\(\\)" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

