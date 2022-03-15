if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112149" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-12-06 15:47:24 +0100 (Wed, 06 Dec 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Geovap Reliance SCADA Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This scripts sends an HTTP GET request to figure out whether a Geovap Reliance SCADA system is installed on the target host, and, if so, which version." );
	script_xref( name: "URL", value: "https://www.reliance-scada.com" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	redir = "/?q=0&l=0";
	if( dir == "/" ) {
		url = redir;
	}
	else {
		url = dir + redir;
	}
	req = http_get( port: port, item: url );
	resp = http_send_recv( data: req, port: port );
	if(IsMatchRegexp( resp, "Reliance 4 Control Server" ) && IsMatchRegexp( resp, "https?://www\\.reliance-scada\\.com" )){
		set_kb_item( name: "geovap/reliance-scada/detected", value: TRUE );
		version = "unknown";
		version_match = eregmatch( pattern: "target=\"_blank\">Reliance</a> ([0-9.]+)(,)?.(Update.([0-9])|.*).\\|", string: resp );
		if( version_match[1] && version_match[4] ){
			version = version_match[1] + " Update " + version_match[4];
		}
		else {
			if( version_match[1] ){
				version = version_match[1];
			}
			else {
				version_match = eregmatch( pattern: "<td>Version</td><td>([0-9.]+) ", string: resp );
				if(version_match[1]){
					version = version_match[1];
				}
			}
		}
		if(version && version != "unknown"){
			set_kb_item( name: "geovap/reliance-scada/version", value: version );
		}
		if( version_match[4] ) {
			exp = "^([0-9.]+).*([0-9])";
		}
		else {
			exp = "^([0-9.]+)";
		}
		register_and_report_cpe( app: "Geovap Reliance SCADA", ver: version, concluded: version_match[0], base: "cpe:/a:geovap:reliance-scada:", expr: exp, insloc: dir, regPort: port, regService: "www", extra: version_match[3] );
		exit( 0 );
	}
}

