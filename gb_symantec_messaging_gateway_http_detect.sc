if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105720" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-12-03 10:06:00 +0100 (Mon, 03 Dec 2012)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Symantec Messaging Gateway Detection (HTTP)" );
	script_tag( name: "summary", value: "Detection of Symantec Messaging Gateway over HTTP.

The script sends a connection request to the server and attempts to detect Symantec Messaging Gateway and
to extract its version." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
url = "/brightmail/viewLogin.do";
res = http_get_cache( item: url, port: port );
if(egrep( pattern: "<title>Symantec Messaging Gateway -&nbsp;Login", string: res, icase: TRUE ) || ( ContainsString( res, "Symantec Messaging Gateway -&nbsp;" ) && ContainsString( res, "Symantec Corporation" ) && ContainsString( res, "images/Symantec_Logo.png" ) ) || ContainsString( res, "<title>Symantec Messaging Gateway -&nbsp;Error 403</title>" )){
	set_kb_item( name: "symantec_smg/detected", value: TRUE );
	set_kb_item( name: "symantec_smg/http/detected", value: TRUE );
	set_kb_item( name: "symantec_smg/http/port", value: port );
	vers = eregmatch( string: res, pattern: "Version ([0-9.]+)", icase: TRUE );
	if(!isnull( vers[1] )){
		set_kb_item( name: "symantec_smg/http/" + port + "/version", value: vers[1] );
		set_kb_item( name: "symantec_smg/http/" + port + "/concluded", value: vers[0] );
	}
}
exit( 0 );

