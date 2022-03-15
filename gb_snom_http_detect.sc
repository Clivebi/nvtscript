if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141999" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-02-15 09:13:25 +0700 (Fri, 15 Feb 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Snom Detection (HTTP)" );
	script_tag( name: "summary", value: "Detection of Snom devices.

  The script sends a HTTP connection request to the server and attempts to detect Snom devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443, 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
res = http_get_cache( port: port, item: "/" );
if(!IsMatchRegexp( res, "^HTTP/1\\.[01] 401" ) && !IsMatchRegexp( res, "<TITLE>snom ?D?[0-9]+" ) && !ContainsString( res, "WWW-Authenticate: Basic realm" ) && !ContainsString( res, "Server: snom embedded" )){
	exit( 0 );
}
mod = eregmatch( pattern: "<TITLE>snom ?(D?[0-9]+)", string: res );
if(isnull( mod[1] )){
	for(i = 0;i < 5;i++){
		req = http_get( port: port, item: "/" );
		res = http_keepalive_send_recv( port: port, data: req );
		mod = eregmatch( pattern: "<TITLE>snom ?(D?[0-9]+)", string: res );
		if(!isnull( mod[1] )){
			break;
		}
	}
	if(!ContainsString( res, "Server: snom embedded" ) && !ContainsString( res, "<TITLE>snom" ) && !ContainsString( res, "Basic realm=\"snom" )){
		exit( 0 );
	}
}
set_kb_item( name: "snom/detected", value: TRUE );
set_kb_item( name: "snom/http/port", value: port );
if(!isnull( mod[1] )){
	set_kb_item( name: "snom/http/" + port + "/model", value: mod[1] );
}
exit( 0 );

