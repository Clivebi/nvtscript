if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10185" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "POP3 Server type and version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 SecuriTeam" );
	script_family( "Service detection" );
	script_dependencies( "find_service2.sc" );
	script_require_ports( "Services/pop3", 110, 995 );
	script_tag( name: "summary", value: "This detects the POP3 Server's type and version by connecting to
  the server and processing the received banner." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("list_array_func.inc.sc");
require("pop3_func.inc.sc");
require("port_service_func.inc.sc");
ports = pop3_get_ports();
for port in ports {
	banner = pop3_get_banner( port: port );
	if(!banner){
		continue;
	}
	if(service_is_unknown( port: port )){
		service_register( port: port, proto: "pop3", message: "A POP3 Server seems to be running on this port." );
	}
	guess = NULL;
	capas = NULL;
	if( get_port_transport( port ) > ENCAPS_IP ) {
		is_tls = TRUE;
	}
	else {
		is_tls = FALSE;
	}
	set_kb_item( name: "pop3/banner/available", value: TRUE );
	set_kb_item( name: "pop3_imap_or_smtp/banner/available", value: TRUE );
	if(ContainsString( banner, "Dovecot " ) && ContainsString( banner, " ready" )){
		set_kb_item( name: "imap_or_pop3/dovecot/detected", value: TRUE );
		set_kb_item( name: "pop3/dovecot/detected", value: TRUE );
		set_kb_item( name: "pop3/" + port + "/dovecot/detected", value: TRUE );
		guess += "\n- Dovecot";
	}
	if(ContainsString( banner, "POP3 on InetServer" )){
		set_kb_item( name: "pop3/avtronics/inetserv/detected", value: TRUE );
		set_kb_item( name: "pop3/" + port + "/avtronics/inetserv/detected", value: TRUE );
		guess += "\n- A-V Tronics InetServ";
	}
	if(ContainsString( banner, "Qpopper" )){
		set_kb_item( name: "pop3/qpopper/detected", value: TRUE );
		set_kb_item( name: "pop3/" + port + "/qpopper/detected", value: TRUE );
		guess += "\n- QPopper";
	}
	if(ContainsString( banner, "POP3" ) && ContainsString( banner, "MDaemon" )){
		set_kb_item( name: "pop3/mdaemon/detected", value: TRUE );
		set_kb_item( name: "pop3/" + port + "/mdaemon/detected", value: TRUE );
		guess += "\n- MDaemon";
	}
	if(ContainsString( banner, "Proxy-POP server (Delegate" )){
		set_kb_item( name: "pop3/delegate/detected", value: TRUE );
		set_kb_item( name: "pop3/" + port + "/delegate/detected", value: TRUE );
		guess += "\n- Delegate";
	}
	if(IsMatchRegexp( banner, "Argosoft Mail Server" )){
		set_kb_item( name: "pop3/argosoft/mailserver/detected", value: TRUE );
		set_kb_item( name: "pop3/" + port + "/argosoft/mailserver/detected", value: TRUE );
		guess += "\n- Argosoft Mail Server";
	}
	if(IsMatchRegexp( banner, "(HCL|Lotus|IBM) Notes POP3 Server" )){
		set_kb_item( name: "pop3/hcl/domino/detected", value: TRUE );
		set_kb_item( name: "pop3/" + port + "/hcl/domino/detected", value: TRUE );
		guess += "\n- HCL | IBM | Lotus Notes";
	}
	if(IsMatchRegexp( banner, "IceWarp" )){
		set_kb_item( name: "pop3/icewarp/mailserver/detected", value: TRUE );
		set_kb_item( name: "pop3/" + port + "/icewarp/mailserver/detected", value: TRUE );
		guess += "\n- IceWarp Mail Server";
	}
	report = "Remote POP3 server banner:\n\n" + banner;
	if(strlen( guess ) > 0){
		report += "\n\nThis is probably:\n" + guess;
	}
	if( is_tls ) {
		capalist = get_kb_list( "pop3/fingerprints/" + port + "/tls_capalist" );
	}
	else {
		capalist = get_kb_list( "pop3/fingerprints/" + port + "/nontls_capalist" );
	}
	if(capalist && is_array( capalist )){
		capalist = sort( capalist );
		for capa in capalist {
			if( !capas ) {
				capas = capa;
			}
			else {
				capas += ", " + capa;
			}
		}
	}
	if(strlen( capas ) > 0){
		capa_report = "\n\nThe remote POP3 server is announcing the following available CAPABILITIES via an ";
		if( is_tls ) {
			capa_report += "encrypted";
		}
		else {
			capa_report += "unencrypted";
		}
		report += capa_report += " connection:\n\n" + capas;
	}
	log_message( port: port, data: report );
}
exit( 0 );

