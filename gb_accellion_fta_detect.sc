if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106030" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2015-07-28 09:48:42 +0700 (Tue, 28 Jul 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Accellion File Transfer Appliance (FTA) Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of a Accellion File Transfer
  Appliance (FTA)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 443 );
for dir in nasl_make_list_unique( "/courier", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/";
	res = http_get_cache( item: url, port: port );
	if(ContainsString( res, "you can manage your application settings," ) && ContainsString( res, "Accellion Corporate" )){
		version = "unknown";
		concl_url = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		vers = eregmatch( string: res, pattern: "<span>FTA([.0-9]+)( \\([A-Z]{2}\\))?</span>", icase: TRUE );
		if( !isnull( vers[1] ) ){
			version = chomp( vers[1] );
			set_kb_item( name: "accellion_fta/version", value: version );
		}
		else {
			url = dir + "/web/1000@/wmLogin.html?";
			req = http_get( port: port, item: url );
			res = http_keepalive_send_recv( port: port, data: req );
			vers = eregmatch( pattern: "js/coreUtils\\.js\\?([0-9_]+)", string: res );
			if(!isnull( vers[1] )){
				v = split( buffer: vers[1], sep: "_", keep: FALSE );
				version = v[0] + "." + substr( v[1], 0, 1 ) + "." + substr( v[1], 2 );
				set_kb_item( name: "accellion_fta/version", value: version );
				concl_url += "\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE );
			}
		}
		set_kb_item( name: "accellion_fta/installed", value: TRUE );
		os_register_and_report( os: "CentOS", version: "6", cpe: "cpe:/o:centos:centos", desc: "Accellion File Transfer Appliance (FTA) Detection (HTTP)", runs_key: "unixoide" );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/h:accellion:secure_file_transfer_appliance:" );
		if(!cpe){
			cpe = "cpe:/h:accellion:secure_file_transfer_appliance";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Accellion File Transfer Appliance (FTA)", version: version, install: install, cpe: cpe, concludedUrl: concl_url, concluded: vers[0] ), port: port );
		exit( 0 );
	}
}
exit( 0 );

