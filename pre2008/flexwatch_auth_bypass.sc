if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.12078" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2003-1160" );
	script_bugtraq_id( 8942 );
	script_xref( name: "OSVDB", value: "2842" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "FlexWATCH Authentication Bypassing" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2005 Noam Rathaus" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "summary", value: "There is a vulnerability in the current version of FlexWATCH that allows an
  attacker to access administrative sections without being required to authenticate." );
	script_tag( name: "impact", value: "An attacker may use this flaw to gain the list of user accounts on this system
  and the ability to reconfigure this service.

  This is done by adding an additional '/' at the beginning of the URL." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
req = http_get( item: "//admin/aindex.htm", port: port );
res = http_keepalive_send_recv( port: port, data: req );
if(res == NULL){
	exit( 0 );
}
find = NASLString( "GoAhead-Webs" );
find2 = NASLString( "admin.htm" );
find3 = NASLString( "videocfg.htm" );
if(ContainsString( res, find ) && ContainsString( res, find2 ) && ContainsString( res, find3 )){
	security_message( port );
	exit( 0 );
}

