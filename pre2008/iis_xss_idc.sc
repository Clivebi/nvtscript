if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11142" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 5900 );
	script_name( "IIS XSS via IDC error" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_active" );
	script_copyright( "Copyright (C) 2002 Geoffroy Raimbault/Lynx Technologies" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_get_http_banner.sc", "cross_site_scripting.sc" );
	script_mandatory_keys( "IIS/banner" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "http://online.securityfocus.com/bid/5900" );
	script_xref( name: "URL", value: "http://www.ntbugtraq.com/default.asp?pid=36&sid=1&A2=ind0210&L=ntbugtraq&F=P&S=&P=1391" );
	script_tag( name: "summary", value: "This IIS Server appears to be vulnerable to a Cross
Site Scripting due to an error in the handling of overlong requests on
an idc file. It is possible to inject Javascript
in the URL, that will appear in the resulting page." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
 of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
 disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
sig = http_get_remote_headers( port: port );
if(sig && !ContainsString( sig, "Server: Microsoft/IIS" )){
	exit( 0 );
}
host = http_host_name( dont_add_port: TRUE );
if(http_get_has_generic_xss( port: port, host: host )){
	exit( 0 );
}
filename = NASLString( "/<script></script>", crap( 334 ), ".idc" );
req = http_get( item: filename, port: port );
r = http_keepalive_send_recv( port: port, data: req );
str = "<script></script>";
if(( IsMatchRegexp( r, "^HTTP/1\\.[01] 200" ) && ContainsString( r, str ) )){
	security_message( port );
}

