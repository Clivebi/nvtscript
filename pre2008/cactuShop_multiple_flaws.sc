if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15461" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2004-1881", "CVE-2004-1882" );
	script_bugtraq_id( 10019, 10020 );
	script_xref( name: "OSVDB", value: "4785" );
	script_xref( name: "OSVDB", value: "4786" );
	script_xref( name: "OSVDB", value: "4787" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "CactuShop XSS and SQL injection flaws" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "Web application abuses" );
	script_require_ports( "Services/www", 80 );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "cross_site_scripting.sc", "global_settings.sc" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade to the latest version of this software." );
	script_tag( name: "summary", value: "The remote host runs CactuShop, an e-commerce web application written in ASP.

The remote version of this software is vulnerable to cross-site scripting
due to a lack of sanitization of user-supplied data in the script
'popuplargeimage.asp'.

Successful exploitation of this issue may allow an attacker to execute
malicious script code on a vulnerable server.

This version may also be vulnerable to SQL injection attacks in
the scripts 'mailorder.asp' and 'payonline.asp'. The user-supplied
input parameter 'strItems' is not filtered before being used in
an SQL query. Thus the query modification through malformed input
is possible.

Successful exploitation of this vulnerability can enable an attacker
to execute commands in the system (via MS SQL the function xp_cmdshell)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_asp( port: port )){
	exit( 0 );
}
host = http_host_name( dont_add_port: TRUE );
if(http_get_has_generic_xss( port: port, host: host )){
	exit( 0 );
}
buf = http_get( item: "/popuplargeimage.asp?strImageTag=<script>foo</script> ", port: port );
r = http_keepalive_send_recv( port: port, data: buf );
if(!r){
	exit( 0 );
}
if(IsMatchRegexp( r, "^HTTP/1\\.[01] 200" ) && egrep( pattern: "<script>foo</script>", string: r )){
	security_message( port );
	exit( 0 );
}

