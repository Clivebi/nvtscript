if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.18424" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2004-2271" );
	script_bugtraq_id( 11620 );
	script_xref( name: "OSVDB", value: "11530" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "MiniShare webserver buffer overflow" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 SensePost" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "MiniShare 1.4.1 and prior versions are affected by a buffer overflow flaw." );
	script_tag( name: "impact", value: "A remote attacker could execute arbitrary commands by sending a specially
  crafted file name in a the GET request." );
	script_tag( name: "affected", value: "Version 1.3.4 and below do not seem to be vulnerable." );
	script_tag( name: "solution", value: "Upgrade to MiniShare 1.4.2 or later." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
res = http_get_cache( item: "/", port: port );
if(!res || !ContainsString( res, "<title>MiniShare</title>" )){
	exit( 0 );
}
if(egrep( string: res, pattern: "<p class=\"versioninfo\"><a href=\"http://minishare\\.sourceforge\\.net/\">MiniShare 1\\.(3\\.([4-9][^0-9]|[0-9][0-9])|4\\.[01][^0-9])" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

