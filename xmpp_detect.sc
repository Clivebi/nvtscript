if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100489" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2010-02-08 23:29:56 +0100 (Mon, 08 Feb 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "XMPP Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Service detection" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc" );
	script_require_ports( "Services/xmpp-client", 5222, "Services/xmpp-server", 5269 );
	script_xref( name: "URL", value: "http://en.wikipedia.org/wiki/Jabber" );
	script_tag( name: "summary", value: "This host is running the Extensible Messaging and Presence Protocol(XMPP)
  (formerly named Jabber). XMPP is an open, XML-based protocol originally aimed at
  near-real-time, extensible instant messaging (IM) and presence information
  (e.g., buddy lists), but now expanded into the broader realm of
  message-oriented middleware." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
func delete_user( soc ){
	req = "<iq id='A4' type='set'>" + "<query xmlns='jabber:iq:register'>" + "<remove/>" + "</query>" + "</iq>";
	send( socket: soc, data: req );
	buf = recv( socket: soc, length: 512 );
	close( soc );
	return 0;
}
ports = service_get_ports( default_port_list: make_list( 5269 ), proto: "xmpp-server" );
host = get_host_name();
for port in ports {
	soc = open_sock_tcp( port );
	if(soc){
		req = "<stream:stream xmlns='jabber:server' " + "xmlns:stream='http://etherx.jabber.org/streams' " + "version='1.0' " + "to='" + host + "'>";
		send( socket: soc, data: req );
		buf = recv( socket: soc, length: 512 );
		close( soc );
		if(!isnull( buf ) && ContainsString( buf, "xmlns:stream=" ) && ContainsString( buf, "jabber:server" )){
			service_register( port: port, ipproto: "tcp", proto: "xmpp-server" );
			set_kb_item( name: "xmpp/installed", value: TRUE );
			log_message( port: port, data: "A XMPP server-to-server service was identified" );
		}
	}
}
service_get_port( default: 5222, proto: "xmpp-client" );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
get_from = "<stream:stream xmlns='jabber:client' " + "xmlns:stream='http://etherx.jabber.org/streams' " + "version='1.0' " + "to='" + host + "'>";
send( socket: soc, data: get_from );
buf = recv( socket: soc, length: 512 );
if(isnull( buf ) || !ContainsString( buf, "xmlns:stream=" ) || !ContainsString( buf, "jabber:client" )){
	close( soc );
	exit( 0 );
}
service_register( port: port, ipproto: "tcp", proto: "xmpp" );
set_kb_item( name: "xmpp/installed", value: TRUE );
service_register( port: port, ipproto: "tcp", proto: "xmpp-client" );
log_message( port: port, data: "A XMPP client-to-server service was identified" );
close( soc );
FROM = eregmatch( pattern: "from='([^']+)'", string: buf );
if(isnull( FROM[1] )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
req = "<stream:stream " + "to='" + FROM[1] + "' " + "xmlns='jabber:client' " + "xmlns:stream='http://etherx.jabber.org/streams'>";
send( socket: soc, data: req );
buf = recv( socket: soc, length: 512 );
if(isnull( buf ) || !ContainsString( buf, "<?xml" ) || ContainsString( buf, "host-unknown" )){
	close( soc );
	exit( 0 );
}
req = "<iq id='A0' type='get'>" + "<query xmlns='jabber:iq:register'/>" + "</iq>";
send( socket: soc, data: req );
buf = recv( socket: soc, length: 512 );
if(isnull( buf ) || !ContainsString( buf, "instructions" )){
	close( soc );
	exit( 0 );
}
vt_strings = get_vt_strings();
USER = vt_strings["lowercase_rand"];
MAIL = vt_strings["lowercase"] + "@example.org";
req = "<iq id='A1' type='set'>" + "<query xmlns='jabber:iq:register'>" + "<username>" + USER + "</username>" + "<password>" + USER + "</password>" + "<name>" + USER + "</name>" + "<email>" + MAIL + "</email>" + "</query>" + "</iq>";
send( socket: soc, data: req );
buf = recv( socket: soc, length: 512 );
if(isnull( buf ) || !ContainsString( buf, "result" )){
	close( soc );
	exit( 0 );
}
req = "<iq id='A2' type='get'>" + "<query xmlns='jabber:iq:auth'>" + "<username>" + USER + "</username>" + "</query>" + "</iq>";
send( socket: soc, data: req );
buf = recv( socket: soc, length: 512 );
if(isnull( buf ) || !ContainsString( buf, USER )){
	delete_user( soc: soc );
	exit( 0 );
}
req = "<iq id='A3' type='set'>" + "<query xmlns='jabber:iq:auth'>" + "<username>" + USER + "</username>" + "<resource>telnet</resource>" + "<password>" + USER + "</password>" + "</query>" + "</iq>";
send( socket: soc, data: req );
buf = recv( socket: soc, length: 512 );
if(!ContainsString( buf, "result" )){
	delete_user( soc: soc );
	exit( 0 );
}
req = "<iq to='" + FROM[1] + "' type='get'>" + "<query xmlns='jabber:iq:version'>" + "</query>" + "</iq>";
send( socket: soc, data: req );
buf = recv( socket: soc, length: 512 );
if(!ContainsString( buf, "<version>" ) || !ContainsString( buf, "<name>" )){
	delete_user( soc: soc );
	exit( 0 );
}
version = eregmatch( pattern: "<version>(.*)</version>", string: buf );
server = eregmatch( pattern: "<name>(.*)</name>", string: buf );
os = eregmatch( pattern: "<os>(.*)</os>", string: buf );
if(!isnull( server[1] )){
	server_name = server[1];
	set_kb_item( name: "xmpp/" + port + "/server", value: server_name );
}
if(!isnull( version[1] )){
	server_version = version[1];
	set_kb_item( name: "xmpp/" + port + "/version", value: server_version );
}
if(!isnull( version[1] )){
	server_os = os[1];
	set_kb_item( name: "xmpp/" + port + "/os", value: server_os );
}
delete_user( soc: soc );
if(server_name && server_version){
	info = "XMPP Server '" + server_name + "' version '" + server_version + "' on '" + server_os + "' was detected.";
}
log_message( port: port, data: info );
exit( 0 );

