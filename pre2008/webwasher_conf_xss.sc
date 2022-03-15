if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.19946" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)" );
	script_bugtraq_id( 9039, 13037 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "WebWasher < 4.4.1 Build 1613 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080, 9090 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.oliverkarow.de/research/WebWasherXSS.txt" );
	script_xref( name: "URL", value: "http://www.oliverkarow.de/research/wwcsm.txt" );
	script_tag( name: "solution", value: "Upgrade to WebWasher CSM 4.4.1 Build 1613 or later." );
	script_tag( name: "summary", value: "The remote host is running the web proxy WebWasher.

  According to its banner, the installed version of WebWasher is prone to
  multiple cross-site scripting flaws." );
	script_tag( name: "impact", value: "Successful exploitation of these issues may allow an attacker
  to execute malicious script code in a user's browser within the context of the affected website." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 9090 );
req = http_get( item: "/vttest-345678.html", port: port );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
if(!res){
	exit( 0 );
}
if(ContainsString( res, "<title>WebWasher - " ) && egrep( pattern: "generated .* by .* \\(WebWasher ([0-3]\\..*|4\\.([0-3] .*|4\\.1 .uild ([0-9][0-9][0-9]|1([0-5][0-9][0-9]|6(0[0-9]|1[0-2])))))\\)", string: res )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

