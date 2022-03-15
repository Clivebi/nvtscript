if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10098" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 776 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-1999-0237" );
	script_name( "guestbook.cgi" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 1999 Mathieu Perrin" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Remove it from /cgi-bin." );
	script_tag( name: "summary", value: "The 'guestbook.cgi' is installed. This CGI has
  a well known security flaw that lets anyone execute arbitrary
  commands with the privileges of the http daemon (root or nobody)." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "Workaround" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
res = http_is_cgi_installed_ka( item: "guestbook.cgi", port: port );
if(res){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

