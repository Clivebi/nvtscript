if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105014" );
	script_version( "$Revision: 11915 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-16 10:05:09 +0200 (Tue, 16 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2014-04-25 12:19:02 +0100 (Fri, 25 Apr 2014)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "SSL/TLS: XMPP 'STARTTLS' Extension Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "SSL and TLS" );
	script_copyright( "This script is Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "xmpp_detect.sc" );
	script_require_ports( "Services/xmpp-client", 5222, "Services/xmpp-server", 5269 );
	script_mandatory_keys( "xmpp/installed" );
	script_tag( name: "summary", value: "Checks if the remote XMPP server/client supports SSL/TLS with the 'STARTTLS' Extension." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://tools.ietf.org/html/rfc6120" );
	exit( 0 );
}
host = get_host_name();
ports = get_kb_list( "Services/xmpp-server" );
if(!ports){
	ports = make_list( 5269 );
}
for port in ports {
	if(!get_port_state( port )){
		continue;
	}
	soc = open_sock_tcp( port );
	if(!soc){
		continue;
	}
	req = "<stream:stream xmlns='jabber:server' " + "xmlns:stream='http://etherx.jabber.org/streams' " + "version='1.0' " + "to='" + host + "'>";
	send( socket: soc, data: req );
	recv = recv( socket: soc, length: 512 );
	if( !ContainsString( recv, "stream:error" ) ){
		req = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>";
		send( socket: soc, data: req );
		recv = recv( socket: soc, length: 256 );
		close( soc );
		if(ContainsString( recv, "<proceed" )){
			set_kb_item( name: "xmpp-server/" + port + "/starttls", value: TRUE );
			set_kb_item( name: "starttls_typ/" + port, value: "xmpp-server" );
			log_message( port: port, data: "The remote XMPP server supports SSL/TLS with the 'STARTTLS' Extension." );
		}
	}
	else {
		close( soc );
	}
}
port = get_kb_item( "Services/xmpp-client" );
if(!port){
	port = 5222;
}
if(!get_tcp_port_state( port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
req = "<stream:stream xmlns='jabber:client' " + "xmlns:stream='http://etherx.jabber.org/streams' " + "version='1.0' " + "to='" + host + "'>";
send( socket: soc, data: req );
recv = recv( socket: soc, length: 512 );
if(ContainsString( recv, "stream:error" )){
	close( soc );
	exit( 0 );
}
req = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>";
send( socket: soc, data: req );
recv = recv( socket: soc, length: 256 );
close( soc );
if(!recv){
	exit( 0 );
}
if(ContainsString( recv, "<proceed" )){
	set_kb_item( name: "xmpp-client/" + port + "/starttls", value: TRUE );
	set_kb_item( name: "starttls_typ/" + port, value: "xmpp-client" );
	log_message( port: port, data: "The remote XMPP client supports SSL/TLS with the 'STARTTLS' Extension." );
}
exit( 0 );

