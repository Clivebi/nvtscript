if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.17975" );
	script_version( "2021-06-18T12:11:02+0000" );
	script_tag( name: "last_modification", value: "2021-06-18 12:11:02 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Service Detection with 'GET' Request" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Michel Arboi" );
	script_family( "Service detection" );
	script_dependencies( "find_service.sc", "find_service_spontaneous.sc", "cifs445.sc", "apache_SSL_complain.sc" );
	script_require_ports( "Services/unknown" );
	script_tag( name: "summary", value: "This plugin performs service detection.

  This plugin is a complement of find_service.nasl. It sends a 'GET' request
  to the remaining unknown services and tries to identify them." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
require("string_hex_func.inc.sc");
require("global_settings.inc.sc");
require("dump.inc.sc");
require("sip.inc.sc");
if(!port = get_kb_item( "Services/unknown" )){
	exit( 0 );
}
if(!get_port_state( port )){
	exit( 0 );
}
if(!service_is_unknown( port: port )){
	exit( 0 );
}
k = "FindService/tcp/" + port + "/get_http";
r = get_kb_item( k + "Hex" );
if( strlen( r ) > 0 ) {
	r = hex2raw( s: r );
}
else {
	r = get_kb_item( k );
}
r_len = strlen( r );
if( r_len == 0 ){
	soc = open_sock_tcp( port );
	if(!soc){
		exit( 0 );
	}
	send( socket: soc, data: "GET / HTTP/1.0\r\n\r\n" );
	r = recv( socket: soc, length: 4096 );
	close( soc );
	r_len = strlen( r );
	if(r_len == 0){
		debug_print( "Service on port ", port, " does not answer to \"GET / HTTP/1.0\"\n" );
		exit( 0 );
	}
	set_kb_item( name: k, value: r );
	rhexstr = hexstr( r );
	if(ContainsString( r, "\0" )){
		set_kb_item( name: k + "Hex", value: rhexstr );
	}
}
else {
	rhexstr = hexstr( r );
}
rbinstr_space = bin2string( ddata: r, noprint_replacement: " " );
rbinstr_nospace = bin2string( ddata: r );
if(IsMatchRegexp( r, "^[ \t\r\n]*<HTML>.*</HTML>" )){
	service_report( port: port, svc: "www", banner: r );
	exit( 0 );
}
if(r == "[TS]\r\n"){
	service_report( port: port, svc: "teamspeak-tcpquery", banner: r );
	exit( 0 );
}
if(r == "gethostbyaddr: Error 0\n"){
	service_register( port: port, proto: "veritas-netbackup-client", message: "Veritas NetBackup Client Service is running on this port" );
	log_message( port: port, data: "Veritas NetBackup Client Service is running on this port" );
	exit( 0 );
}
if(ContainsString( r, "GET / HTTP/1.0 : ERROR : INVALID-PORT" ) || ContainsString( r, "GET/HTTP/1.0 : ERROR : INVALID-PORT" )){
	service_report( port: port, svc: "auth", banner: r );
	exit( 0 );
}
if(ContainsString( r, "Host" ) && ContainsString( r, "is not allowed to connect to this" ) && ( ContainsString( tolower( r ), "mysql" ) || ContainsString( tolower( r ), "mariadb" ) )){
	if( ContainsString( tolower( r ), "mysql" ) ){
		text = "A MySQL";
	}
	else {
		if( ContainsString( tolower( r ), "mariadb" ) ){
			text = "A MariaDB";
		}
		else {
			text = "A MySQL/MariaDB";
		}
	}
	service_register( port: port, proto: "mysql", message: text + " server seems to be running on this port but it rejects connection from the scanner." );
	log_message( port: port, data: text + " server seems to be running on this port but it rejects connection from the scanner." );
	exit( 0 );
}
if(ContainsString( r, "Host" ) && ContainsString( r, " is blocked " ) && ContainsString( r, "mysqladmin flush-hosts" )){
	service_register( port: port, proto: "mysql", message: "A MySQL/MariaDB server seems to be running on this port but the scanner IP has been blacklisted. Run 'mysqladmin flush-hosts' if you want complete tests." );
	log_message( port: port, data: "A MySQL server seems to be running on this port but the scanner IP has been blacklisted. Run 'mysqladmin flush-hosts' if you want complete tests." );
	exit( 0 );
}
if(!IsMatchRegexp( rbinstr_space, "[0-9.]+ [0-9a-z]+@[0-9a-z]+ release" ) && ( ( ContainsString( r, "mysql_native_password" ) && ContainsString( r, "Got packets out of order" ) ) || ContainsString( rhexstr, "001b000001ff8404476f74207061636b657473206f7574206f66206f72646572" ) || ContainsString( rhexstr, "006d7973716c5f6e61746976655f70617373776f726400" ) )){
	service_register( port: port, proto: "mysql", message: "A MySQL/MariaDB server seems to be running on this port." );
	log_message( port: port, data: "A MySQL/MariaDB server seems to be running on this port." );
	exit( 0 );
}
if(IsMatchRegexp( r, "^JNB30" ) && ord( r[5] ) == 14 && ord( r[6] == 3 )){
	service_register( port: port, proto: "jnbproxy", message: "ColdFusion jnbproxy is running on this port." );
	log_message( port: port, data: "ColdFusion jnbproxy is running on this port." );
	exit( 0 );
}
if(ContainsString( r, "Asterisk Call Manager" )){
	service_register( port: port, proto: "asterisk", message: "An Asterisk Call Manager server is running on this port." );
	log_message( port: port, data: "An Asterisk Call Manager server is running on this port." );
	exit( 0 );
}
if(r_len == 3 && ( r[2] == "\x10" || r[2] == "\x0b" ) || r == "\x78\x01\x07" || r == "\x10\x73\x0A" || r == "\x78\x01\x07" || r == "\x08\x40\x0c"){
	service_register( port: port, proto: "msdtc", message: "A MSDTC server seems to be running on this port" );
	log_message( port: port, data: "A MSDTC server seems to be running on this port" );
	exit( 0 );
}
if(( r_len == 5 || r_len == 6 ) && r[3] == "\0" && r[0] != "\0" && r[1] != "\0" && r[2] != "\0"){
	service_register( port: port, proto: "msdtc", message: "A MSDTC server seems to be running on this port" );
	log_message( port: port, data: "A MSDTC server seems to be running on this port" );
	exit( 0 );
}
if(r == "\x01Permission denied" || ( ContainsString( r, "lpd " ) && ContainsString( r, "Print-services" ) )){
	service_report( port: port, svc: "lpd", message: "An LPD server is running on this port" );
	log_message( port: port, data: "An LPD server is running on this port" );
	exit( 0 );
}
if(r == "GET / HTTP/1.0\r\n\r\n"){
	service_report( port: port, svc: "echo", banner: r );
	exit( 0 );
}
if(IsMatchRegexp( r, "^HTTP/1\\.[01] +[1-5][0-9][0-9] " )){
	service_report( port: port, svc: "www", banner: r );
	exit( 0 );
}
if(IsMatchRegexp( r, "^[0-9][0-9][0-9]-?[ \t]" )){
	debug_print( "\"3 digits\" found on port ", port, " in response to GET\n" );
	service_register( port: port, proto: "three_digits" );
	exit( 0 );
}
if(IsMatchRegexp( r, "^RFB [0-9]" )){
	service_report( port: port, svc: "vnc" );
	replace_kb_item( name: "vnc/banner/" + port, value: r );
	exit( 0 );
}
if(match( string: r, pattern: "Language received from client:*Setlocale:*" )){
	service_report( port: port, svc: "websm" );
	exit( 0 );
}
if(banner = egrep( string: rbinstr_space, pattern: "invalid command \\(code=([0-9]+), len=([0-9]+)\\)" )){
	service_register( port: port, proto: "sphinxapi", message: "A Sphinx search server seems to be running on this port" );
	log_message( port: port, data: "A Sphinx search server seems to be running on this port" );
	set_kb_item( name: "sphinxsearch/" + port + "/sphinxapi/banner", value: banner );
	exit( 0 );
}
if(r_len > 10 && r[1] == "\0" && r[2] == "\0" && r[3] == "\0" && eregmatch( string: rbinstr_space, pattern: "^.\\s{4}[0-9.]+(-(id[0-9]+-)?release \\([0-9a-z-]+\\)| [0-9a-z]+@[0-9a-z]+ release)" )){
	service_register( port: port, proto: "sphinxql", message: "A Sphinx search server (MySQL listener) seems to be running on this port" );
	log_message( port: port, data: "A Sphinx search server (MySQL listener) seems to be running on this port" );
	set_kb_item( name: "sphinxsearch/" + port + "/sphinxql/banner", value: rbinstr_space );
	exit( 0 );
}
if(match( string: r, pattern: "*<stream:stream*xmlns:stream='http://etherx.jabber.org/streams'*" )){
	if( ContainsString( r, "jabber:server" ) ){
		service_register( port: port, proto: "xmpp-server", message: "A XMPP server-to-server service seems to be running on this port" );
		log_message( port: port, data: "A XMPP server-to-server service seems to be running on this port" );
		exit( 0 );
	}
	else {
		if( ContainsString( r, "jabber:client" ) ){
			service_register( port: port, proto: "xmpp-client", message: "A XMPP client-to-server service seems to be running on this port" );
			log_message( port: port, data: "A XMPP client-to-server service seems to be running on this port" );
			exit( 0 );
		}
		else {
			log_message( port: port, data: "A XMPP client-to-server or server-to-server service seems to be running on this port" );
			service_register( port: port, proto: "xmpp-server", message: "A XMPP client-to-server or server-to-server service seems to be running on this port" );
			service_register( port: port, proto: "xmpp-client", message: "A XMPP client-to-server or server-to-server service seems to be running on this port" );
			exit( 0 );
		}
	}
}
if(ContainsString( r, "Active Internet connections" ) || ContainsString( r, "Active connections" )){
	service_register( port: port, proto: "netstat", message: "A netstat service seems to be running on this port." );
	log_message( port: port, data: "A netstat service seems to be running on this port." );
	exit( 0 );
}
if(ContainsString( r, "obby_welcome" )){
	service_register( port: port, proto: "obby", message: "A obby service seems to be running on this port." );
	log_message( port: port, data: "A obby service seems to be running on this port." );
	exit( 0 );
}
if(match( string: r, pattern: "*OK Cyrus IMSP version*ready*" )){
	service_register( port: port, proto: "imsp", message: "A Cyrus IMSP service seems to be running on this port." );
	log_message( port: port, data: "A Cyrus IMSP service seems to be running on this port." );
	exit( 0 );
}
if(match( string: r, pattern: "RESPONSE/None/*/application/json:*{\"status\": *, \"message\": \"*\"}" )){
	service_register( port: port, proto: "umcs", message: "A Univention Management Console Server service seems to be running on this port." );
	log_message( port: port, data: "A Univention Management Console Server service seems to be running on this port." );
	exit( 0 );
}
if(ContainsString( rbinstr_nospace, "DRb::DRbConnError" )){
	service_register( port: port, proto: "drb", message: "A Distributed Ruby (dRuby/DRb) service seems to be running on this port." );
	log_message( port: port, data: "A Distributed Ruby (dRuby/DRb) service seems to be running on this port." );
	exit( 0 );
}
if(IsMatchRegexp( port, "^929[0-2]$" ) && IsMatchRegexp( r, "^0[0-2]$" )){
	service_register( port: port, proto: "iee-rsgw", message: "A 'Raw scanning to peripherals with IEEE 1284.4 specifications' service seems to be running on this port." );
	log_message( port: port, data: "A 'Raw scanning to peripherals with IEEE 1284.4 specifications' service seems to be running on this port." );
	exit( 0 );
}
if(port == 515 && IsMatchRegexp( rhexstr, "^ff$" )){
	service_register( port: port, proto: "printer", message: "A LPD service seems to be running on this port." );
	log_message( port: port, data: "A LPD service seems to be running on this port." );
	exit( 0 );
}
if(ContainsString( r, "(Thread" ) && ( ContainsString( r, "Notify Wlan Link " ) || ContainsString( r, "Notify Eth Link " ) || ContainsString( r, "Received unknown command on socket" ) || ContainsString( r, "fsfsFlashFileHandleOpen" ) || ContainsString( r, "Found existing handle " ) || ContainsString( r, "After waiting approx. " ) || ContainsString( r, "Timer fired at " ) || ContainsString( r, "ControlSocketServerInstructClientToLeave" ) || ( ContainsString( r, "WFSAPI" ) && ContainsString( r, "File not found" ) ) )){
	service_register( port: port, proto: "wifiradio-setup", message: "A WiFi radio setup service seems to be running on this port." );
	log_message( port: port, data: "A WiFi radio setup service seems to be running on this port." );
	exit( 0 );
}
if(ContainsString( r, "IOR:010000002600000049444c3a536f70686f734d6573736167696e672f4d657373616765526f75746572" )){
	service_register( port: port, proto: "sophos_rms", message: "A Sophos Remote Messaging / Management Server seems to be running on this port." );
	log_message( port: port, data: "A Sophos Remote Messaging / Management Server seems to be running on this port." );
	exit( 0 );
}
if(ContainsString( r, "<<<check_mk>>>" ) || ContainsString( r, "<<<uptime>>>" ) || ContainsString( r, "<<<services>>>" ) || ContainsString( r, "<<<mem>>>" )){
	replace_kb_item( name: "check_mk_agent/banner/" + port, value: r );
	service_register( port: port, proto: "check_mk_agent", message: "A Check_MK Agent seems to be running on this port." );
	log_message( port: port, data: "A Check_MK Agent seems to be running on this port." );
	exit( 0 );
}
if(IsMatchRegexp( r, "^\\.NET" ) && ( ContainsString( r, "customErrors" ) || ContainsString( r, "RemotingException" ) )){
	service_register( port: port, proto: "remoting", message: "A .NET remoting service seems to be running on this port." );
	log_message( port: port, data: "A .NET remoting service seems to be running on this port." );
	exit( 0 );
}
if(IsMatchRegexp( r, "^-ERR wrong number of arguments for 'get' command" ) || egrep( string: r, pattern: "^-ERR unknown command 'Host:'" ) || IsMatchRegexp( r, "^-DENIED Redis is running in protected mode" )){
	service_register( port: port, proto: "redis", message: "A Redis server seems to be running on this port." );
	log_message( port: port, data: "A Redis server seems to be running on this port." );
	exit( 0 );
}
if(ContainsString( r, "Connection from client using unsupported AMQP attempted" ) || ContainsString( r, "amqp:decode-error" )){
	service_register( port: port, proto: "amqp", message: "A AMQP service seems to be running on this port." );
	log_message( port: port, data: "An AMQP service seems to be running on this port." );
	exit( 0 );
}
if(ContainsString( r, "ActiveMQ" ) && ( ContainsString( r, "PlatformDetails" ) || ContainsString( r, "StackTraceEnable" ) || ContainsString( r, "ProviderVersion" ) || ContainsString( r, "TcpNoDelayEnabled" ) )){
	set_kb_item( name: "ActiveMQ/JMS/banner/" + port, value: rbinstr_nospace );
	service_register( port: port, proto: "activemq_jms", message: "A ActiveMQ JMS service seems to be running on this port." );
	log_message( port: port, data: "A ActiveMQ JMS service seems to be running on this port." );
	exit( 0 );
}
if(port == 5556 && ContainsString( r, ":-ERR Error reading from socket: Unknown protocol exception" )){
	service_register( port: port, proto: "nodemanager", message: "A Weblogic NodeManager service seems to be running on this port." );
	log_message( port: port, data: "A Weblogic NodeManager service seems to be running on this port." );
	exit( 0 );
}
if(IsMatchRegexp( r, "Nsure Audit .* \\[.*\\]" )){
	service_register( port: port, proto: "naudit", message: "A Novell Audit Secure Logging Server service seems to be running on this port." );
	log_message( port: port, data: "A Novell Audit Secure Logging Server service seems to be running on this port." );
	exit( 0 );
}
if(IsMatchRegexp( r, "^ERROR\r\nERROR\r\nERROR\r\n$" )){
	service_register( port: port, proto: "memcached", message: "A Memcached service seems to be running on this port." );
	log_message( port: port, data: "A Memcached service seems to be running on this port." );
	exit( 0 );
}
if(( port == 8083 || port == 9099 ) && rhexstr == "556e6b6e6f776e206d657373616765"){
	service_register( port: port, proto: "myris", message: "A Myris service seems to be running on this port." );
	log_message( port: port, data: "A Myris service seems to be running on this port." );
	exit( 0 );
}
if(ereg( pattern: "^(Mon|Tue|Wed|Thu|Fri|Sat|Sun|Lun|Mar|Mer|Jeu|Ven|Sam|Dim) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|D[eé]c|F[eé]v|Avr|Mai|Ao[uû]) *(0?[0-9]|[1-3][0-9]) [0-9]+:[0-9]+(:[0-9]+)?( *[ap]m)?( +[A-Z]+)? [1-2][0-9][0-9][0-9].?.?$", string: r ) || ereg( pattern: "^[0-9][0-9] +(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|D[eé]c|F[eé]v|Avr|Mai|Ao[uû]) +[1-2][0-9][0-9][0-9] +[0-9]+:[0-9]+:[0-9]+( *[ap]m)? [A-Z0-9]+.?.?$", string: r, icase: TRUE ) || IsMatchRegexp( r, "^(0?[0-9]|[1-2][0-9]|3[01])-(0[1-9]|1[0-2])-20[0-9][0-9][\r\n]*$" ) || IsMatchRegexp( r, "^([01]?[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9] (19|20)[0-9][0-9]-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])[ \t\r\n]*$" ) || ereg( pattern: "^(Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), (January|February|March|April|May|June|July|August|September|October|November|December) ([0-9]|[1-3][0-9]), [1-2][0-9][0-9][0-9] .*", string: r ) || ereg( pattern: "^[0-9][0-9]?:[0-9][0-9]:[0-9][0-9] [AP]M [0-9][0-9]?/[0-9][0-9]?/[0-2][0-9][0-9][0-9].*$", string: r ) || IsMatchRegexp( r, "^([01]?[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9] +(0[1-9]|[12][0-9]|3[01])\\.(0[1-9]|1[0-2])\\.(19|20)[0-9][0-9][ \t\r\n]*$" )){
	service_register( port: port, proto: "daytime" );
	log_message( port: port, data: "Daytime is running on this port" );
	exit( 0 );
}
if(IsMatchRegexp( rhexstr, "^0000000209000000010000000000000000$" )){
	service_register( port: port, proto: "ipmi-rmcp", message: "A IPMI RMCP service seems to be running on this port." );
	log_message( port: port, data: "A IMPI RMCP service seems to be running on this port." );
	exit( 0 );
}
if(IsMatchRegexp( rhexstr, "^220000802000530054004100520054005F00480041004E0044005300480041004B0045000000" )){
	service_register( port: port, proto: "sccm-control", message: "A SCCM Remote Control (control) service seems to be running on this port." );
	log_message( port: port, data: "A SCCM Remote Control (control) service seems to be running on this port." );
	exit( 0 );
}
if(IsMatchRegexp( r, "^root@metasploitable:/# " )){
	service_register( port: port, proto: "rootshell", message: "A root shell of Metasploitable seems to be running on this port." );
	log_message( port: port, data: "A root shell of Metasploitable seems to be running on this port." );
	exit( 0 );
}
if(egrep( string: r, pattern: "^[0-9]+ (all|carp|em0|enc|enc0|lo|lo0|pflog0|pflog|\\-) [0-9]+ [0-9]+$" )){
	service_register( port: port, proto: "pfstatd", message: "A pfstatd service seems to be running on this port." );
	log_message( port: port, data: "A pfstatd service seems to be running on this port." );
	exit( 0 );
}
if(IsMatchRegexp( rhexstr, "^000001..52..020A..08A3800410..180020..2A.*10001A9002" ) && ContainsString( r, "-----BEGIN PUBLIC KEY-----" ) && ContainsString( r, "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ" )){
	service_register( port: port, proto: "r1soft_backupagent", message: "A R1Soft Backup Agent seems to be running on this port." );
	log_message( port: port, data: "A R1Soft Backup Agent seems to be running on this port." );
	exit( 0 );
}
if(( IsMatchRegexp( r, "^RPY [0-9] [0-9]" ) && ContainsString( r, "Content-Type: application/" ) ) || ( ContainsString( r, "<profile uri=" ) && ContainsString( r, "http://iana.org/beep/" ) ) || ContainsString( r, "Content-Type: application/beep" )){
	service_register( port: port, proto: "beep", message: "A service supporting the Blocks Extensible Exchange Protocol (BEEP) seems to be running on this port." );
	log_message( port: port, data: "A service supporting the Blocks Extensible Exchange Protocol (BEEP) seems to be running on this port." );
	exit( 0 );
}
if(IsMatchRegexp( r, "^bsh % " ) || IsMatchRegexp( r, "^BeanShell " ) || ContainsString( r, "- by Pat Niemeyer (pat@pat.net)" )){
	service_register( port: port, proto: "beanshell", message: "A BeanShell listener service seems to be running on this port." );
	log_message( port: port, data: "A BeanShell listener service seems to be running on this port." );
	set_kb_item( name: "beanshell_listener/detected", value: TRUE );
	exit( 0 );
}
if(IsMatchRegexp( r, "^w0256" ) && ( r_len == 261 || r_len == 263 )){
	service_register( port: port, proto: "wifiradio-unknown", message: "An unknown service related to a WiFi radio seems to be running on this port." );
	log_message( port: port, data: "An unknown service related to a WiFi radio seems to be running on this port." );
	exit( 0 );
}
if(port == 23 && rhexstr == "436f6e6e656374696f6e20726566757365640d0a"){
	service_register( port: port, proto: "telnet", message: "A telnet service rejecting the access of the scanner seems to be running on this port." );
	log_message( port: port, data: "A telnet service rejecting the access of the scanner seems to be running on this port." );
	exit( 0 );
}
if(sip_verify_banner( data: r )){
	service_register( port: port, proto: "sip", message: "A service supporting the SIP protocol seems to be running on this port." );
	log_message( port: port, data: "A service supporting the SIP protocol seems to be running on this port." );
	exit( 0 );
}
if(rhexstr == "10000000a5a50000d400600100000000"){
	service_register( port: port, proto: "mep", message: "A service supporting the Metric Exchange Protocol (MEP) seems to be running on this port." );
	log_message( port: port, data: "A service supporting the Metric Exchange Protocol (MEP) seems to be running on this port." );
	exit( 0 );
}
chargen_found = 0;
for chargen_pattern in make_list( "!\"#$%&\'()*+,-./",
	 "ABCDEFGHIJ",
	 "abcdefg",
	 "0123456789",
	 ":;<=>?@",
	 "KLMNOPQRSTUVWXYZ" ) {
	if(ContainsString( r, chargen_pattern )){
		chargen_found++;
	}
}
if(chargen_found > 2){
	replace_kb_item( name: "chargen/tcp/" + port + "/banner", value: chomp( r ) );
	service_register( port: port, proto: "chargen", message: "A chargen service seems to be running on this port." );
	log_message( port: port, data: "A chargen service seems to be running on this port." );
	exit( 0 );
}
if(rhexstr == "0300000902f0802180"){
	service_register( port: port, proto: "ms-wbt-server", message: "A service (e.x. Xrdp) supporting the Microsoft Remote Desktop Protocol (RDP) seems to be running on this port." );
	log_message( port: port, data: "A service (e.x. Xrdp) supporting the Microsoft Remote Desktop Protocol (RDP) seems to be running on this port." );
	set_kb_item( name: "rdp/" + port + "/isxrdp", value: TRUE );
	exit( 0 );
}
if(port == 5441 && ( ContainsString( r, "HEATINGNODE" ) || ContainsString( r, "COOLINGNODE" ) || ContainsString( r, "CTL FLOW MAX" ) || ContainsString( r, "OCC FLOW" ) || ContainsString( r, "$paneldefault" ) || ContainsString( r, "NEGATIVE" ) || ContainsString( r, "POSITIVE" ) )){
	service_register( port: port, proto: "siemens-bms", message: "A service related to Siemens Building Management Systems seems to be running on this port." );
	log_message( port: port, data: "A service related to Siemens Building Management Systems seems to be running on this port." );
	exit( 0 );
}
if(rhexstr == "0000006400000018"){
	service_register( port: port, proto: "omapi", message: "A service supporting the Object Management Application Programming Interface (OMAPI) protocol seems to be running on this port." );
	log_message( port: port, data: "A service supporting the Object Management Application Programming Interface (OMAPI) protocol seems to be running on this port." );
	exit( 0 );
}
if(rhexstr == "0000100309000103090000000000ffe80000000c00010004000000020000000000000002"){
	service_register( port: port, proto: "comvault-complete-backup", message: "A Comvault Complete Backup & Recovery service seems to be running on this port." );
	log_message( port: port, data: "A Comvault Complete Backup & Recovery service seems to be running on this port." );
	exit( 0 );
}
if(rhexstr == "ff14506f7274206973206f7574206f662072616e676500ff14506f7274206973206f7574206f662072616e676500ff14506f7274206973206f7574206f662072616e676500ff14506f7274206973206f7574206f662072616e676500ff14506f7274206973206f7574206f662072616e676500"){
	service_register( port: port, proto: "digi-usb", message: "A Digi AnywhereUSB/14 service seems to be running on this port." );
	log_message( port: port, data: "A Digi AnywhereUSB/14 service seems to be running on this port." );
	exit( 0 );
}
if(rhexstr == "24000002439d3a7f00011000b3b71ecda6e711e8b933e6e42ba3c7af299f98ada83b11e8a62b7f470668bcb7 "){
	service_register( port: port, proto: "digi-usb", message: "A MariaDB galera cluster service seems to be running on this port." );
	log_message( port: port, data: "A MariaDB galera cluster service seems to be running on this port." );
	exit( 0 );
}
if(IsMatchRegexp( r, "^:.* NOTICE AUTH :\\*\\*\\* Looking up your hostname" ) || IsMatchRegexp( r, "^ERROR :Your host is trying to \\(re\\)connect too fast -- throttled\\." ) || IsMatchRegexp( r, "^:.* 451 GET :You have not registered" ) || IsMatchRegexp( r, "^:.* NOTICE IP_LOOKUP :\\*\\*\\* Looking up your hostname\\.\\.\\." ) || IsMatchRegexp( r, "^:.* NOTICE \\* :\\*\\*\\* Looking up your hostname\\.\\.\\." ) || IsMatchRegexp( r, "^ERROR :Trying to reconnect too fast." ) || ( IsMatchRegexp( r, "^ERROR :Closing Link:" ) && ContainsString( r, "(Throttled: Reconnecting too fast)" ) )){
	service_register( port: port, proto: "irc", message: "An IRC server seems to be running on this port." );
	log_message( port: port, data: "An IRC server seems to be running on this port." );
	exit( 0 );
}
if(port == 514 && ContainsString( r, "getnameinfo: Temporary failure in name resolution" )){
	service_register( port: port, proto: "rsh", message: "A rsh service seems to be running on this port." );
	log_message( port: port, data: "A rsh service seems to be running on this port." );
	exit( 0 );
}
if(IsMatchRegexp( rhexstr, "^01010018.{16}00000000.{64}0{32}.{64}$" )){
	service_register( port: port, proto: "nping-echo", message: "An nping-echo server seems to be running on this port." );
	log_message( port: port, data: "An nping-echo server seems to be running on this port." );
	exit( 0 );
}
if(IsMatchRegexp( rhexstr, "013939393946463142.." )){
	service_register( port: port, proto: "automated-tank-gauge", message: "A Automated Tank Gauge (ATG) service seems to be running on this port." );
	log_message( port: port, data: "A Automated Tank Gauge (ATG) service seems to be running on this port." );
	exit( 0 );
}
if(r == "Finger online user list request denied.\r\n\n" || r == "Unable to find specified user.\r\n" || egrep( string: r, pattern: "Line\\s+User\\s+Host", icase: TRUE ) || egrep( string: r, pattern: "Login\\s+Name\\s+TTY", icase: TRUE ) || eregmatch( string: r, pattern: "^Login name: GET", icase: FALSE )){
	service_register( port: port, proto: "finger", message: "A finger service seems to be running on this port." );
	log_message( port: port, data: "A finger service seems to be running on this port." );
	exit( 0 );
}
if(ContainsString( r, "Integrated port" ) && ContainsString( r, "Printer Type" ) && ContainsString( r, "Print Job Status" )){
	service_register( port: port, proto: "fingerd-printer", message: "A printer related finger service seems to be running on this port." );
	log_message( port: port, data: "A printer related finger service seems to be running on this port." );
	set_kb_item( name: "fingerd-printer/" + port + "/banner", value: ereg_replace( string: r, pattern: "(^\r\n|\r\n$)", replace: "" ) );
	exit( 0 );
}
if(IsMatchRegexp( rhexstr, "^(07000000000400000[0-2]0[0-6]){1,}$" )){
	service_register( port: port, proto: "dicom", message: "A Digital Imaging and Communications in Medicine (DICOM) service seems to be running on this port." );
	log_message( port: port, data: "A Digital Imaging and Communications in Medicine (DICOM) service seems to be running on this port." );
	exit( 0 );
}
if(r == "JDWP-Handshake"){
	service_register( port: port, proto: "jdwp", message: "A Java Debug Wired Protocol (JDWP) service is running at this port." );
	log_message( port: port, data: "A Java Debug Wired Protocol (JDWP) service is running at this port." );
	exit( 0 );
}
if(IsMatchRegexp( r, "^@RSYNCD: [0-9.]+" ) || IsMatchRegexp( r, "^You are not welcome to use rsync from " ) || IsMatchRegexp( r, "^rsync: (link_stat |error |.+unknown option)" ) || IsMatchRegexp( r, "rsync error: (syntax or usage error|some files/attrs were not transferred) " ) || IsMatchRegexp( r, "rsync\\s+version [0-9.]+\\s+protocol version [0-9.]+" )){
	service_register( port: port, proto: "rsync", message: "A service supporting the rsync protocol is running at this port." );
	log_message( port: port, data: "A service supporting the rsync protocol is running at this port." );
	exit( 0 );
}
if(ContainsString( r, "Visionsoft Audit on Demand Service" )){
	service_register( port: port, proto: "visionsoft-audit", message: "A Visionsoft Audit on Demand Service is running at this port." );
	log_message( port: port, data: "A Visionsoft Audit on Demand Service is running at this port." );
	exit( 0 );
}
if(egrep( pattern: "^OK WorkgroupShare.+server ready", string: r, icase: FALSE )){
	service_register( port: port, proto: "workgroupshare", message: "A WorkgroupShare Server is running at this port." );
	replace_kb_item( name: "workgroupshare/" + port + "/banner", value: chomp( r ) );
	log_message( port: port, data: "A WorkgroupShare Server is running at this port." );
	exit( 0 );
}
if(IsMatchRegexp( r, "^HPE? (OpenView Storage )?Data Protector" )){
	service_register( port: port, proto: "hp_dataprotector", message: "HP/HPE (OpenView Storage) Data Protector seems to be running on this port" );
	replace_kb_item( name: "hp_dataprotector/" + port + "/banner", value: chomp( r ) );
	log_message( port: port, data: "HP/HPE (OpenView Storage) Data Protector seems to be running on this port" );
	exit( 0 );
}
if(IsMatchRegexp( r, "^This is not a HTTP port$" )){
	service_register( port: port, proto: "elasticsearch", message: "An Elasticsearch Binary API / inter-cluster communication service seems to be running on this port." );
	log_message( port: port, data: "An Elasticsearch Binary API / inter-cluster communication service seems to be running on this port." );
	exit( 0 );
}
if(IsMatchRegexp( rhexstr, "^5[19]000000$" )){
	service_register( port: port, proto: "fw1-topology", message: "A Check Point FireWall-1 (FW-1) SecureRemote (SecuRemote) service seems to be running on this port" );
	log_message( port: port, data: "A Check Point FireWall-1 (FW-1) SecureRemote (SecuRemote) service seems to be running on this port" );
	exit( 0 );
}
if(IsMatchRegexp( r, "^(\\|/dev/[a-z0-9/-]+\\|[^|]*\\|[^|]*\\|[^|]\\|)+$" )){
	service_report( port: port, svc: "hddtemp" );
	exit( 0 );
}
if(IsMatchRegexp( rhexstr, "^15030[0-3]00020[1-2]..$" ) || IsMatchRegexp( rhexstr, "^1500000732$" ) || IsMatchRegexp( rhexstr, "^150301$" )){
	service_register( port: port, proto: "ssl", message: "A service responding with an SSL/TLS alert seems to be running on this port." );
	log_message( port: port, data: "A service responding with an SSL/TLS alert seems to be running on this port." );
	exit( 0 );
}
if(IsMatchRegexp( rhexstr, "0000....1f8b08000000000000007d" )){
	service_register( port: port, proto: "powerfolder_data", message: "A PowerFolder P2P data service is running at this port." );
	log_message( port: port, data: "A PowerFolder P2P data service is running at this port." );
	exit( 0 );
}
exit( 0 );

