if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105007" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2014-04-09 15:29:22 +0100 (Wed, 09 Apr 2014)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "SSL/TLS: IMAP 'STARTTLS' Command Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "SSL and TLS" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "imap4_banner.sc" );
	script_require_ports( "Services/imap", 143 );
	script_mandatory_keys( "imap/banner/available" );
	script_tag( name: "summary", value: "Checks if the remote IMAP server supports SSL/TLS with the 'STARTTLS' command." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://tools.ietf.org/html/rfc2595" );
	exit( 0 );
}
require("imap_func.inc.sc");
require("port_service_func.inc.sc");
port = imap_get_port( default: 143 );
if(get_port_transport( port ) > ENCAPS_IP){
	exit( 0 );
}
soc = imap_open_socket( port: port );
if(!soc){
	exit( 0 );
}
tag++;
send( socket: soc, data: "A0" + tag + " STARTTLS\r\n" );
for(;buf = recv_line( socket: soc, length: 2048 );){
	n++;
	if(eregmatch( pattern: "^A0" + tag + " OK", string: buf )){
		STARTTLS = TRUE;
	}
	if(n > 10){
		break;
	}
}
if( STARTTLS ){
	set_kb_item( name: "imap/starttls/supported", value: TRUE );
	set_kb_item( name: "imap/" + port + "/starttls", value: TRUE );
	set_kb_item( name: "starttls_typ/" + port, value: "imap" );
	report = "The remote IMAP server supports SSL/TLS with the 'STARTTLS' command.";
	capalist = get_kb_list( "imap/fingerprints/" + port + "/nontls_capalist" );
	if(capalist && NASLTypeof( capalist ) == "array"){
		capalist = sort( capalist );
		capa_report = "";
		for capa in capalist {
			if( !capa_report ) {
				capa_report = capa;
			}
			else {
				capa_report += ", " + capa;
			}
		}
		if(capa_report){
			report = NASLString( report, "\\n\\nThe remote IMAP server is announcing the following CAPABILITIES before sending the 'STARTTLS' command:\\n\\n", capa_report );
		}
	}
	set_kb_item( name: "Host/SNI/" + port + "/force_disable", value: 1 );
	soc = socket_negotiate_ssl( socket: soc );
	tag++;
	if(soc){
		send( socket: soc, data: "A0" + tag + " CAPABILITY\r\n" );
		banner = recv( socket: soc, length: 4096 );
		tag++;
		imap_close_socket( socket: soc, id: tag );
		capas = egrep( string: banner, pattern: "\\* CAPABILITY.+IMAP4rev1", icase: TRUE );
		capas = chomp( capas );
		if(capas){
			capa_report = "";
			capas = split( buffer: capas, sep: " ", keep: FALSE );
			capas = sort( capas );
			for capa in capas {
				if(capa == "*" || capa == "CAPABILITY" || capa == "IMAP4rev1"){
					continue;
				}
				if( !capa_report ) {
					capa_report = capa;
				}
				else {
					capa_report += ", " + capa;
				}
				set_kb_item( name: "imap/fingerprints/" + port + "/tls_capalist", value: capa );
			}
			if(capa_report){
				report = NASLString( report, "\\n\\nThe remote IMAP server is announcing the following CAPABILITIES after sending the 'STARTTLS' command:\\n\\n", capa_report );
			}
		}
	}
	log_message( port: port, data: report );
}
else {
	tag++;
	imap_close_socket( socket: soc, id: tag );
	set_kb_item( name: "imap/starttls/not_supported", value: TRUE );
	set_kb_item( name: "imap/starttls/not_supported/port", value: port );
}
exit( 0 );

