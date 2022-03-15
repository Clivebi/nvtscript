if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113280" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-10-25 14:49:10 +0200 (Thu, 25 Oct 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Yealink IP Phone Detection (HTTP)" );
	script_tag( name: "summary", value: "Detection of Yealink IP Phone

  The script attempts to identify Yealink IP Phone via HTTP banner to extract the model and version
  number." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
url = "/servlet?m=mod_listener&p=login&q=loginForm";
buf = http_get_cache( port: port, item: url );
if(IsMatchRegexp( buf, "try again [0-9]+ minutes later" ) && IsMatchRegexp( buf, "You are not authorized" )){
	url = "/servlet?p=login&q=loginForm&jumpto=status";
	buf = http_get_cache( port: port, item: url );
}
if(IsMatchRegexp( buf, "Server: yealink" ) || IsMatchRegexp( buf, "<title>Yealink" )){
	version = "unknown";
	model = "unknown";
	set_kb_item( name: "yealink_ipphone/detected", value: TRUE );
	set_kb_item( name: "yealink_ipphone/http/detected", value: TRUE );
	set_kb_item( name: "yealink_ipphone/http/port", value: port );
	mo = eregmatch( pattern: "g_phonetype[ ]*=[ ]*[\"\']([A-Z0-9_-]+)[\"\']", string: buf );
	if( !isnull( mo[1] ) ){
		model = chomp( mo[1] );
		concluded = mo[0];
	}
	else {
		mo = eregmatch( pattern: "<script>T\\(\"[^\")]+ ([A-Z0-9_-]+)\"\\)", string: buf );
		if(!isnull( mo[1] )){
			model = chomp( mo[1] );
			concluded = mo[0];
		}
	}
	vers = eregmatch( pattern: "g_str[Ff]irmware[ ]*=[ ]*[\"\']([0-9.]+)[\"\']", string: buf );
	if( !isnull( vers[1] ) ){
		version = vers[1];
		concluded += "\n" + vers[0];
	}
	else {
		vers = eregmatch( pattern: "language[/].+[.]js[?]([0-9.]+)", string: buf );
		if(!isnull( vers[1] )){
			version = vers[1];
			concluded += "\n" + vers[0];
		}
	}
	set_kb_item( name: "yealink_ipphone/http/" + port + "/model", value: model );
	set_kb_item( name: "yealink_ipphone/http/" + port + "/version", value: version );
	if(concluded){
		set_kb_item( name: "yealink_ipphone/http/" + port + "/concluded", value: concluded );
	}
}
exit( 0 );

