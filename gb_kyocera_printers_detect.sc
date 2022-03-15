if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103707" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-05-08 11:31:24 +0100 (Wed, 08 May 2013)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Kyocera Printer Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of Kyocera Printers.

  The script sends a connection request to the remote host and
  attempts to detect if the remote host is a Kyocera printer." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("kyocera_printers.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
urls = get_ky_detect_urls();
for url in keys( urls ) {
	pattern = urls[url];
	url = ereg_replace( string: url, pattern: "(#--avoid-dup[0-9]+--#)", replace: "" );
	buf = http_get_cache( item: url, port: port );
	if(!buf || !IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" )){
		continue;
	}
	if(kyo = eregmatch( pattern: pattern, string: buf, icase: TRUE )){
		if(!isnull( kyo[1] )){
			concluded = kyo[0];
			model = kyo[1];
			set_kb_item( name: "kyocera_printer/installed", value: TRUE );
			set_kb_item( name: "kyocera_printer/port", value: port );
			set_kb_item( name: "kyocera_model", value: model );
			cpe_model = tolower( model );
			cpe = "cpe:/h:kyocera:" + cpe_model;
			cpe = str_replace( string: cpe, find: " ", replace: "_" );
			register_product( cpe: cpe, location: port + "/tcp", port: port, service: "www" );
			log_message( port: port, data: "The remote Host is a Kyocera " + model + " printer device.\\nCPE: " + cpe + "\\nConcluded: " + concluded );
			pref = get_kb_item( "global_settings/exclude_printers" );
			if(pref == "yes"){
				log_message( port: port, data: "The remote host is a printer. The scan has been disabled against this host.\nIf you want to scan the remote host, uncheck the \"Exclude printers from scan\" option and re-scan it." );
				set_kb_item( name: "Host/dead", value: TRUE );
			}
			exit( 0 );
		}
	}
}
exit( 0 );

