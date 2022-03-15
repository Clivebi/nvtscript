if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814217" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-09-19 14:33:52 +0530 (Wed, 19 Sep 2018)" );
	script_name( "Dell Laser Multi Function Printer(MFP) Printers Detection (HTTP)" );
	script_tag( name: "summary", value: "Detection of Dell Laser MFP Printer.

  The script sends a connection request to the remote host and attempts to
  detect if the remote host is a Dell Laser MFP Printer." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_xref( name: "URL", value: "https://www.dell.com" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
res = http_get_cache( item: "/default.html", port: port );
if(IsMatchRegexp( res, "<TITLE>Dell Laser MFP.*</TITLE>" ) && ContainsString( res, "prn_status.htm" )){
	set_kb_item( name: "Dell/Laser/MFP/Printer/Running", value: TRUE );
	set_kb_item( name: "Dell_Printer/Port", value: port );
	printer_model = eregmatch( pattern: "Dell Laser MFP ([0-9A-Za-z]+)<", string: res );
	if(printer_model[1]){
		model = printer_model[1];
		set_kb_item( name: "Dell_Printer_Model", value: model );
		cpe_printer_model = tolower( model );
		cpe = "cpe:/h:dell:" + cpe_printer_model;
		cpe = str_replace( string: cpe, find: " ", replace: "_" );
	}
	if(!model){
		model = "Unknown Dell model";
		cpe = "cpe:/h:dell:unknown_model";
	}
	url = "/printer_info.htm";
	res = http_get_cache( item: url, port: port );
	firm_ver = eregmatch( pattern: ">Printer Firmware Version.*>([0-9.]+)<.*Engine Firmware Version", string: res );
	if(firm_ver[1]){
		set_kb_item( name: "dell_mfp_printer/firmware_ver", value: firm_ver[1] );
		cpe = cpe + ":" + firm_ver[1];
	}
	register_product( cpe: cpe, location: port + "/tcp", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Dell Laser MFP " + model + " Printer Device", version: firm_ver[1], install: port + "/tcp", cpe: cpe, concluded: printer_model[0] ), port: port );
	pref = get_kb_item( "global_settings/exclude_printers" );
	if(pref == "yes"){
		log_message( port: port, data: "The remote host is a printer. The scan has been disabled against this host.\nIf you want to scan the remote host, uncheck the \"Exclude printers from scan\" option and re-scan it." );
		set_kb_item( name: "Host/dead", value: TRUE );
	}
}
exit( 0 );

