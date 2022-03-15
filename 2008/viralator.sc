if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.80093" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_bugtraq_id( 3495 );
	script_cve_id( "CVE-2001-0849" );
	script_name( "viralator" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Renaud Deraison" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The CGI 'viralator.cgi' is installed.

  Some versions of this CGI are don't check properly the user input and allow anyone to execute arbitrary commands
  with the privileges of the web server" );
	script_tag( name: "solution", value: "Upgrade this script to version 0.9pre2 or newer." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://marc.info/?l=bugtraq&m=100463639800515&w=2" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
res = http_is_cgi_installed_ka( item: "viralator.cgi", port: port );
if(res){
	security_message( port );
}

