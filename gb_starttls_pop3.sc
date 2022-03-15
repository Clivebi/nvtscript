if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105008" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2014-04-09 16:29:22 +0100 (Wed, 09 Apr 2014)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "SSL/TLS: POP3 'STLS' Command Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "SSL and TLS" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "popserver_detect.sc" );
	script_require_ports( "Services/pop3", 110 );
	script_mandatory_keys( "pop3/banner/available" );
	script_tag( name: "summary", value: "Checks if the remote POP3 server supports SSL/TLS with the 'STLS' command." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://tools.ietf.org/html/rfc2595" );
	exit( 0 );
}
require("pop3_func.inc.sc");
require("port_service_func.inc.sc");
port = pop3_get_port( default: 110 );
if(get_port_transport( port ) > ENCAPS_IP){
	exit( 0 );
}
soc = pop3_open_socket( port: port );
if(!soc){
	exit( 0 );
}
send( socket: soc, data: "STLS\r\n" );
for(;buf = recv_line( socket: soc, length: 2048 );){
	n++;
	if(eregmatch( pattern: "^\\+OK", string: buf, icase: FALSE )){
		STARTTLS = TRUE;
	}
	if(n > 10){
		break;
	}
}
if( STARTTLS ){
	set_kb_item( name: "pop3/starttls/supported", value: TRUE );
	set_kb_item( name: "pop3/" + port + "/starttls", value: TRUE );
	set_kb_item( name: "starttls_typ/" + port, value: "pop3" );
	report = "The remote POP3 server supports SSL/TLS with the 'STLS' command.";
	capalist = get_kb_list( "pop3/fingerprints/" + port + "/nontls_capalist" );
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
			report = NASLString( report, "\\n\\nThe remote POP3 server is announcing the following CAPABILITIES before sending the 'STLS' command:\\n\\n", capa_report );
		}
	}
	set_kb_item( name: "Host/SNI/" + port + "/force_disable", value: 1 );
	soc = socket_negotiate_ssl( socket: soc );
	if(soc){
		send( socket: soc, data: "CAPA\r\n" );
		capabanner = recv_line( socket: soc, length: 4096 );
		capabanner = chomp( capabanner );
		if(capabanner && ( capabanner == "+OK" || ContainsString( tolower( capabanner ), "capability list follows" ) || ContainsString( tolower( capabanner ), "List of capabilities follows" ) || ContainsString( tolower( capabanner ), "capa list follows" ) || ContainsString( capabanner, "list follows" ) || ContainsString( capabanner, "Here's what I can do" ) )){
			for(;capabanner = recv_line( socket: soc, length: 4096 );){
				o++;
				capabanner = chomp( capabanner );
				if(capabanner && capabanner != "."){
					set_kb_item( name: "pop3/fingerprints/" + port + "/tls_capalist", value: capabanner );
				}
				if(o > 128){
					break;
				}
			}
			capalist = get_kb_list( "pop3/fingerprints/" + port + "/tls_capalist" );
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
			}
			if(capa_report){
				report = NASLString( report, "\\n\\nThe remote POP3 server is announcing the following CAPABILITIES after sending the 'STLS' command:\\n\\n", capa_report );
			}
		}
		pop3_close_socket( socket: soc );
	}
	log_message( port: port, data: report );
}
else {
	pop3_close_socket( socket: soc );
	set_kb_item( name: "pop3/starttls/not_supported", value: TRUE );
	set_kb_item( name: "pop3/starttls/not_supported/port", value: port );
}
exit( 0 );

