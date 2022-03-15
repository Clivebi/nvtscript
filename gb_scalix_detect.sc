if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105102" );
	script_version( "2020-08-25T06:34:32+0000" );
	script_tag( name: "last_modification", value: "2020-08-25 06:34:32 +0000 (Tue, 25 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-11-03 13:25:47 +0100 (Mon, 03 Nov 2014)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Scalix Detection (HTTP, SMTP, IMAP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "smtpserver_detect.sc", "imap4_banner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, "Services/smtp", 25, 465, 587, "Services/imap", 143, 993 );
	script_tag( name: "summary", value: "The script sends a connection request to the server and
  attempts to extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
require("smtp_func.inc.sc");
require("imap_func.inc.sc");
require("misc_func.inc.sc");
func _report( port, version, location, concluded, service ){
	if(!version || version == ""){
		return;
	}
	if(!location){
		location = port + "/tcp";
	}
	set_kb_item( name: "scalix/" + port + "/version", value: version );
	set_kb_item( name: "scalix/installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:scalix:scalix:" );
	if(!cpe){
		cpe = "cpe:/a:scalix:scalix";
	}
	register_product( cpe: cpe, location: location, port: port, service: service );
	log_message( data: build_detection_report( app: "Scalix", version: version, install: location, cpe: cpe, concluded: concluded ), port: port );
	exit( 0 );
}
ports = http_get_ports( default_port_list: make_list( 80 ) );
for port in ports {
	if(http_is_cgi_scan_disabled()){
		break;
	}
	url = "/webmail/";
	buf = http_get_cache( item: url, port: port );
	if(buf && ContainsString( buf, "<title>Login to Scalix Web Access" )){
		vers = "unknown";
		buf_sp = split( buffer: buf, keep: FALSE );
		for(i = 0;i < max_index( buf_sp );i++){
			if(ContainsString( buf_sp[i], "color:#666666;font-size:9px" )){
				if(version = eregmatch( pattern: "([0-9.]+)", string: buf_sp[i + 1] )){
					_report( port: port, version: version[1], location: "/webmail/", concluded: version[0], service: "www" );
					break;
				}
			}
		}
	}
}
ports = smtp_get_ports();
for port in ports {
	banner = smtp_get_banner( port: port );
	if(banner && ContainsString( banner, "ESMTP Scalix SMTP" )){
		if(version = eregmatch( pattern: "ESMTP Scalix SMTP Relay ([0-9.]+);", string: banner )){
			_report( port: port, version: version[1], concluded: "SMTP banner", service: "smtp" );
		}
	}
}
ports = imap_get_ports();
for port in ports {
	banner = imap_get_banner( port: port );
	if(banner && ContainsString( banner, "Scalix IMAP server" )){
		if(version = eregmatch( pattern: "Scalix IMAP server ([0-9.]+)", string: banner )){
			_report( port: port, version: version[1], concluded: "IMAP banner", service: "imap" );
		}
	}
}
exit( 0 );

