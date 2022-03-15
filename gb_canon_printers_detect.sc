if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803719" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-06-20 13:42:47 +0530 (Thu, 20 Jun 2013)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Canon Printer Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of Canon Printers.

  The script sends a connection request to the remote host and
  attempts to detect if the remote host is a Canon printer." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
buf = http_get_cache( item: "/index.html", port: port );
buf2 = http_get_cache( item: "/", port: port );
if(( ContainsString( buf, ">Canon" ) && ContainsString( buf, ">Copyright CANON INC" ) && ContainsString( buf, "Printer" ) ) || ContainsString( buf, "CANON HTTP Server" ) || ( ContainsString( buf2, "erver: Catwalk" ) && ContainsString( buf2, "com.canon.meap.service" ) ) || ( ( ( ContainsString( buf2, "canonlogo.gif\" alt=\"CANON\"" ) ) || ( ContainsString( buf2, "canonlogo.gif\" alt=" ) ) || ( ContainsString( buf2, "canonlogo.gif" ) && ContainsString( buf2, "Series</title>" ) ) ) && ContainsString( buf2, ">Copyright CANON INC" ) )){
	set_kb_item( name: "canon_printer/installed", value: TRUE );
	set_kb_item( name: "canon_printer/port", value: port );
	printer_model = eregmatch( pattern: ">(Canon.[A-Z0-9]+).[A-Za-z]+<", string: buf );
	if(printer_model[1]){
		model = printer_model[1];
		set_kb_item( name: "canon_printer_model", value: model );
		cpe_printer_model = tolower( model );
		cpe = "cpe:/h:canon:" + cpe_printer_model;
		cpe = str_replace( string: cpe, find: " ", replace: "_" );
	}
	if(!model){
		printer_model = eregmatch( pattern: "<span id=\"deviceName\".* / ([A-Za-z0-9 ]+) / ", string: buf2 );
		if(!printer_model[1]){
			printer_model = eregmatch( pattern: "<span id=\"deviceName\">([^/<]+)", string: buf2 );
		}
		if(printer_model[1]){
			if( ContainsString( printer_model[1], "&nbsp;" ) ){
				canon_model = ereg_replace( pattern: "&nbsp;", replace: " ", string: printer_model[1] );
			}
			else {
				canon_model = printer_model[1];
			}
			model = chomp( canon_model );
			set_kb_item( name: "canon_printer_model", value: model );
			cpe_printer_model = tolower( model );
			cpe = "cpe:/h:canon:" + cpe_printer_model;
			cpe = str_replace( string: cpe, find: " ", replace: "_" );
		}
	}
	if(!model){
		model = "Unknown Canon model";
		cpe = "cpe:/h:canon:unknown_model";
	}
	firm_ver = eregmatch( pattern: "nowrap>([0-9.]+)</td>", string: buf );
	if(firm_ver[1]){
		set_kb_item( name: "canon_printer/firmware_ver", value: firm_ver[1] );
		cpe = cpe + ":" + firm_ver[1];
	}
	register_product( cpe: cpe, location: port + "/tcp", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Canon " + model + " Printer Device", version: firm_ver[1], install: port + "/tcp", cpe: cpe, concluded: printer_model[0] ), port: port );
	pref = get_kb_item( "global_settings/exclude_printers" );
	if(pref == "yes"){
		log_message( port: port, data: "The remote host is a printer. The scan has been disabled against this host.\nIf you want to scan the remote host, uncheck the \"Exclude printers from scan\" option and re-scan it." );
		set_kb_item( name: "Host/dead", value: TRUE );
	}
}
exit( 0 );

