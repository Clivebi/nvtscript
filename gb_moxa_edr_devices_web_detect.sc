if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140015" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-10-25 10:43:45 +0200 (Tue, 25 Oct 2016)" );
	script_name( "Moxa EDR Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script performs HTTP based detection of Moxa EDR devices." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_asp( port: port )){
	exit( 0 );
}
buf = http_get_cache( port: port, item: "/Login.asp" );
if(!buf || !ContainsString( buf, "<TITLE>Moxa EDR</TITLE>" )){
	exit( 0 );
}
hw_cpe = "cpe:/h:moxa:edr";
os_cpe = "cpe:/o:moxa:edr";
set_kb_item( name: "moxa_edr/detected", value: TRUE );
version = "unknown";
if( ContainsString( buf, "Industrial Secure Router" ) || ContainsString( buf, "var ProjectModel" ) ){
	if( ContainsString( buf, "var ProjectModel" ) ){
		mn = eregmatch( pattern: "var ProjectModel = ([0-9]+);", string: buf );
		if(!isnull( mn[1] )){
			typ = mn[1];
			if( typ == 1 ) {
				mod = "G903";
			}
			else {
				if( typ == 2 ) {
					mod = "G902";
				}
				else {
					if(typ == 3){
						mod = "810";
					}
				}
			}
			hw_cpe += "-" + mod;
			os_cpe += "_" + mod;
			model = "EDR-" + mod;
			set_kb_item( name: "moxa_edr/model", value: model );
		}
	}
	else {
		mod = eregmatch( pattern: "var Model(Nmae|Name) = '(EDR-[^']+)';", string: buf );
		if(!isnull( mod[1] )){
			model = mod[1];
			set_kb_item( name: "moxa_edr/model", value: model );
			cpe_mod = split( buffer: model, sep: "-", keep: FALSE );
			if(!isnull( cpe_mod[1] )){
				cpe_model = cpe_mod[1];
				hw_cpe += "-" + cpe_model;
				os_cpe += "_" + cpe_model;
			}
		}
	}
}
else {
	if(ContainsString( buf, "EtherDevice Secure Router" )){
		lines = split( buf );
		x = 0;
		for line in lines {
			x++;
			if(ContainsString( line, "Moxa EtherDevice Secure Router" )){
				for(i = 0;i < 10;i++){
					if(ContainsString( lines[x + i], "EDR-" )){
						mod = eregmatch( pattern: "(EDR-[^ <]+)", string: lines[x + i] );
						if(!isnull( mod[1] )){
							model = mod[1];
							set_kb_item( name: "moxa_edr/model", value: model );
							cpe_mod = split( buffer: model, sep: "-", keep: FALSE );
							if(!isnull( cpe_mod[1] )){
								cpe_model = cpe_mod[1];
								hw_cpe += "-" + cpe_model;
								os_cpe += "_" + cpe_model;
							}
						}
					}
				}
			}
		}
	}
}
if(!model){
	model = "EDR Unknown Model";
	os_cpe += "_unknown_model";
}
os_cpe += "_firmware";
os_register_and_report( os: "Moxa " + model + " Firmware", cpe: os_cpe, desc: "Moxa EDR Detection", runs_key: "unixoide" );
register_product( cpe: hw_cpe, location: "/", port: port, service: "www" );
log_message( data: build_detection_report( app: "Moxa " + model, version: version, install: "/", cpe: hw_cpe ), port: port );
exit( 0 );

