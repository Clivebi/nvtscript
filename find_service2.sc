if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11153" );
	script_version( "2021-08-09T06:49:35+0000" );
	script_tag( name: "last_modification", value: "2021-08-09 06:49:35 +0000 (Mon, 09 Aug 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Service Detection with 'HELP' Request'" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Michel Arboi" );
	script_family( "Service detection" );
	script_dependencies( "find_service1.sc", "find_service_3digits.sc", "rpcinfo.sc", "dcetest.sc", "apache_SSL_complain.sc" );
	script_require_ports( "Services/unknown" );
	script_tag( name: "summary", value: "This plugin performs service detection.

  This plugin is a complement of find_service.nasl. It sends a 'HELP'
  request to the remaining unknown services and tries to identify them." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("global_settings.inc.sc");
require("port_service_func.inc.sc");
require("string_hex_func.inc.sc");
port = get_kb_item( "Services/unknown" );
if(!port){
	exit( 0 );
}
if(!get_port_state( port )){
	exit( 0 );
}
if(!service_is_unknown( port: port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
send( socket: soc, data: "HELP\r\n" );
r = recv( socket: soc, length: 4096 );
close( soc );
k = "FindService/tcp/" + port + "/get_http";
rget = get_kb_item( k + "Hex" );
if( strlen( rget ) > 0 ) {
	rget = hex2raw( s: rget );
}
else {
	rget = get_kb_item( k );
}
if(!r){
	debug_print( "service on port ", port, " does not answer to \"HELP\"\n" );
	exit( 0 );
}
k = "FindService/tcp/" + port + "/help";
set_kb_item( name: k, value: r );
rhexstr = hexstr( r );
if(ContainsString( r, "\0" )){
	set_kb_item( name: k + "Hex", value: rhexstr );
}
if(IsMatchRegexp( r, "^\\( success \\( [0-9] [0-9] \\(.*\\) \\(.*" )){
	service_register( port: port, proto: "subversion" );
	log_message( port: port, data: "A SubVersion server is running on this port" );
	exit( 0 );
}
if(ContainsString( r, "Invalid protocol verification, illegal ORMI request" )){
	service_register( port: port, proto: "oracle_application_server" );
	log_message( port: port, data: "An Oracle Application Server is running on this port" );
	exit( 0 );
}
if(ContainsString( r, raw_string( 0x51, 0x00, 0x00, 0x00 ) ) && port == 264){
	service_register( port: port, proto: "checkpoint_fw_ng_gettopo_port" );
	log_message( port: port, data: "A CheckPoint FW NG gettopo_port service is running on this port" );
	exit( 0 );
}
if(ContainsString( r, raw_string( 0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x0a ) ) && port == 2144){
	service_register( port: port, proto: "hyperic_hq_agent" );
	log_message( port: port, data: "The Hyperic HQ Agent service is running on this port" );
	exit( 0 );
}
if(ContainsString( r, raw_string( 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x7F ) )){
	service_register( port: port, proto: "salt_master" );
	log_message( port: port, data: "Salt Master (http://www.saltstack.com/) is running on this port" );
	exit( 0 );
}
if(ContainsString( r, raw_string( 0x29, 0x01, 0x00, 0x00, 0x06, 0x02, 0x00, 0x00, 0x00, 0xA4, 0x00, 0x00, 0x52, 0x53, 0x41, 0x31, 0x00, 0x04, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00 ) )){
	service_register( port: port, proto: "g_data_p2p_update_distribution" );
	log_message( port: port, data: "G-data P2P update distribution is running on this port" );
	exit( 0 );
}
if(ContainsString( r, raw_string( 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x32, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x09, 0x5F, 0x00, 0x00, 0x00, 0x68, 0x7A, 0x29, 0x57, 0x2D, 0x38, 0x23, 0x50, 0x52, 0x20, 0x27, 0x2E, 0x57, 0x35, 0x5F, 0x47, 0x6A, 0x7D, 0x25, 0x39, 0x65, 0x37, 0x2E, 0x79, 0x56, 0x6E, 0x67, 0x4D, 0x5E, 0x4F, 0x3E, 0x3B, 0x57, 0x78, 0x44, 0x21, 0x3A, 0x32, 0x32, 0x27, 0x7F, 0x61, 0x4A, 0x31, 0x65, 0x59, 0x3F, 0x7A, 0x75, 0x33, 0x38, 0x5D, 0x43, 0x40, 0x30, 0x55, 0x74, 0x7D, 0x62, 0x28, 0x26, 0x48, 0x43, 0x60, 0x6C, 0x51, 0x70, 0x5A, 0x39, 0x74, 0x4A, 0x42, 0x40, 0x47, 0x7F, 0x3F, 0x39, 0x2F, 0x4B, 0x2A, 0x26, 0x38, 0x5F, 0x25, 0x36, 0x65, 0x20, 0x6A, 0x6A, 0x44, 0x33, 0x61, 0x37, 0x25, 0x78, 0x56, 0x2B, 0x2D, 0x54, 0x4A, 0x33, 0x00, 0x00, 0x00, 0x00 ) ) && port == 8402){
	service_register( port: port, proto: "commvault_client_event_manager" );
	log_message( port: port, data: "The Commvault Client Event Manager service is running on this port" );
	exit( 0 );
}
if(ContainsString( r, raw_string( 0x94, 0x00, 0x00, 0x00, 0xF4, 0xFF, 0xFF, 0xFF, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xA5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x3E, 0xF9, 0xE6, 0xB9, 0x9B, 0xFE, 0x6B, 0x7C, 0x2D, 0x69, 0x87, 0x74, 0x0B, 0xF3, 0x10, 0x66, 0x87, 0xC2, 0xA8, 0x59, 0xA6, 0x18, 0xB4, 0xBD, 0xAE, 0xBF, 0x7A, 0x5A, 0x3A, 0xF4, 0x23, 0xAC, 0xF6, 0xE4, 0xFC, 0xDE, 0x59, 0x80, 0x0C, 0x9F, 0x05, 0xDD, 0xBC, 0xE5, 0x7E, 0xDE, 0x7D, 0x19, 0xDC, 0x7D, 0x34, 0x2F, 0xEC, 0x2D, 0x63, 0x5D, 0x2F, 0x4E, 0x35, 0x26, 0xDD, 0x7C, 0xC3, 0xAB, 0xAC, 0x13, 0x28, 0xD3, 0xB3, 0xA5, 0xBA, 0xF0, 0xFD, 0xD6, 0xFA, 0x22, 0xBF, 0x4D, 0xF2, 0x4D, 0xA6, 0x70, 0x08, 0x98, 0x0E, 0x7D, 0x82, 0x59, 0xD7, 0xF3, 0x87, 0x3B, 0x9E, 0xC7, 0xC5, 0x95, 0x06, 0x54, 0x61, 0x43, 0xED, 0xF9, 0x57, 0xBB, 0x50, 0x25, 0x1A, 0xB6, 0xA6, 0x61, 0xCE, 0xBD, 0xC1, 0x29, 0x69, 0x76, 0xD5, 0x30, 0x10, 0xCC, 0x60, 0x40, 0x48, 0xEF, 0x8D, 0xE0, 0xAC, 0x76, 0xFF, 0xFE, 0xFF, 0xFE, 0xFF, 0xFF, 0xFB, 0xFF, 0xCE, 0xBE, 0xAC, 0xAD, 0xFF, 0xFF, 0x5B, 0xFF, 0xFF, 0xFF, 0xFD, 0xF9 ) ) && ( port == 2800 || port == 2500 || port == 2501 || port == 2502 || port == 2503 || port == 2506 || port == 2505 || port == 2600 || port == 2801 || port == 2900 )){
	service_register( port: port, proto: "CCure" );
	log_message( port: port, data: "A Ccure security management solution is running on this port" );
	exit( 0 );
}
if(ContainsString( r, "error NOT AUTHORIZED YET" )){
	service_register( port: port, proto: "DMAIL_Admin" );
	log_message( port: port, data: "The remote host is running a DMAIL Administrative service on this port" );
	exit( 0 );
}
if(ContainsString( r, "From Server : MESSAGE RECEIVED" )){
	service_register( port: port, proto: "shixxnote" );
	log_message( port: port, data: "A shixxnote server is running on this port" );
	exit( 0 );
}
if(ContainsString( r, "xmlns='jabber:client'" )){
	service_register( port: port, proto: "ejabberd" );
	log_message( port: port, data: "An ejabberd server is running on this port" );
	exit( 0 );
}
if(ContainsString( r, "Request with malformed data; connection closed" )){
	service_register( port: port, proto: "moodle-chat-daemom" );
	log_message( port: port, data: "A Moodle Chat Daemon is running on this port" );
	exit( 0 );
}
if(ContainsString( r, "CONEXANT SYSTEMS, INC." ) && ContainsString( r, "ACCESS RUNNER ADSL TERMINAL" )){
	service_register( port: port, proto: "conexant_telnet" );
	log_message( port: port, data: "A Conexant configuration interface is running on this port" );
	exit( 0 );
}
if(IsMatchRegexp( r, "^0\\.[67]\\.[0-9] LOG\0 {16}" )){
	service_register( port: port, proto: "partimage" );
	log_message( port: port, data: "Partimage is running on this port. It requires login." );
	exit( 0 );
}
if(IsMatchRegexp( r, "^0\\.[67]\\.[0-9]\0 {16}" )){
	service_register( port: port, proto: "partimage" );
	log_message( port: port, data: "Partimage is running on this port. It does not require login." );
	exit( 0 );
}
if(ContainsString( r, "%x%s%p%nh%u%c%z%Z%t%i%e%g%f%a%C" )){
	service_register( port: port, proto: "egcd" );
	log_message( port: port, data: "egcd is running on this port" );
	exit( 0 );
}
if(ContainsString( rhexstr, "f6ffff10" ) && strlen( r ) < 6){
	service_register( port: port, proto: "BackupExec" );
	log_message( port: port, data: "A BackupExec Agent is running on this port" );
	exit( 0 );
}
if(r == "\x00\x00\x00\x03"){
	service_register( port: port, proto: "godm" );
	log_message( port: port, data: "AIX Global ODM (a component from HACMP) is running on this port" );
	exit( 0 );
}
if(ContainsString( r, "UNKNOWN COMMAND\n" )){
	service_register( port: port, proto: "clamd" );
	log_message( port: port, data: "A clamd daemon (part of ClamAntivirus) is running on this port" );
	exit( 0 );
}
if(ContainsString( r, "AdsGone 200" ) && ContainsString( r, "HTML Ad" )){
	service_register( port: port, proto: "adsgone" );
	log_message( port: port, data: "An AdsGone proxy server is running on this port" );
	exit( 0 );
}
if(egrep( pattern: "^Centra AudioServer", string: r )){
	service_register( port: port, proto: "centra" );
	log_message( port: port, data: "A Centra audio server is running on this port" );
	exit( 0 );
}
if(ContainsString( r, "Ok\r\n500 Command unknown" )){
	service_register( port: port, proto: "smtp" );
	log_message( port: port, data: "An SMTP server is running on this port" );
	exit( 0 );
}
if(ContainsString( r, "VERIFY = F$VERIFY" ) || ContainsString( r, "* OK dovecot ready." )){
	service_register( port: port, proto: "imap" );
	log_message( port: port, data: "An IMAP server is running on this port" );
	exit( 0 );
}
if(ContainsString( r, "421 Server is temporarily unavailable - pleast try again later" ) && ContainsString( r, "421 Service closing control connection" )){
	service_register( port: port, proto: "ftp-disabled" );
	log_message( port: port, data: "A (disabled) FTP server is running on this port" );
	exit( 0 );
}
if(egrep( pattern: "RTSP/1\\.0 505( Protocol | RTSP | )Version [nN]ot [sS]upported", string: r )){
	service_register( port: port, proto: "rtsp" );
	log_message( port: port, data: "A RTSP (shoutcast) server is running on this port" );
	exit( 0 );
}
if(ContainsString( r, "ERR INVALID-ARGUMENT" ) && ContainsString( r, "ERR UNKNOWN-COMMAND" )){
	service_register( port: port, proto: "nut" );
	log_message( port: port, data: "A Network UPS Tool (NUT) server is running on this port" );
	exit( 0 );
}
if(ContainsString( r, "\x80\x3d\x01\x03\x01" )){
	service_register( port: port, proto: "osiris" );
	log_message( port: port, data: "An Osiris daemon is running on this port" );
	exit( 0 );
}
if("\x15\x03\x01" == r){
	service_register( port: port, proto: "APC_PowerChuteBusinessEdition" );
	log_message( port: port, data: "APC Power Chute Business Edition is running on this port" );
	exit( 0 );
}
if(ContainsString( r, "CAP PH\r\n" )){
	service_register( port: port, proto: "BrightMail_AntiSpam" );
	log_message( port: port, data: "BrightMail AntiSpam is running on this port" );
	exit( 0 );
}
if(ContainsString( r, "\xea\xdd\xbe\xef" )){
	service_register( port: port, proto: "veritas-netbackup-client" );
	log_message( port: port, data: "Veritas NetBackup Client Service is running on this port" );
	exit( 0 );
}
if(ContainsString( r, "\x70\x5f\x0a\x10\x01" )){
	service_register( port: port, proto: "cisco-ris-data-collector" );
	log_message( port: port, data: "A CISCO RIS Data Collector is running on this port" );
	exit( 0 );
}
if(ContainsString( tolower( r ), "hello, this is quagga" )){
	service_register( port: port, proto: "quagga" );
	log_message( port: port, data: "The quagga daemon is listening on this port" );
	exit( 0 );
}
if(ContainsString( r, "Hello\n" )){
	service_register( port: port, proto: "musicdaemon" );
	log_message( port: port, data: "musicdaemon is listening on this port" );
	exit( 0 );
}
if(egrep( pattern: "^220.*Administrator Service ready\\.", string: r ) || egrep( pattern: "^220.*eSafe@.*Service ready", string: r )){
	service_register( port: port, proto: "smtp" );
	exit( 0 );
}
if(ContainsString( r, "Integrated port" ) && ContainsString( r, "Printer Type" ) && ContainsString( r, "Print Job Status" )){
	service_register( port: port, proto: "fingerd-printer", message: "A printer related finger service seems to be running on this port." );
	log_message( port: port, data: "A printer related finger service seems to be running on this port." );
	set_kb_item( name: "fingerd-printer/" + port + "/banner", value: ereg_replace( string: r, pattern: "(^\r\n|\r\n$)", replace: "" ) );
	exit( 0 );
}
if(ContainsString( r, "Invalid password!!!" ) || ContainsString( r, "Incorrect password!!!" )){
	service_register( port: port, proto: "wollf" );
	log_message( port: port, data: "A Wollf backdoor is running on this port" );
	exit( 0 );
}
if(ContainsString( r, "version report" )){
	service_register( port: port, proto: "gnocatan" );
	log_message( port: port, data: "A gnocatan game server is running on this port" );
	exit( 0 );
}
if(ContainsString( r, "Welcome on mldonkey command-line" )){
	service_register( port: port, proto: "mldonkey-telnet" );
	log_message( port: port, data: "A MLdonkey telnet interface is running on this port" );
	exit( 0 );
}
if(egrep( pattern: "^connected\\. .*, version:", string: r )){
	service_register( port: port, proto: "subseven" );
	log_message( port: port, data: "A subseven backdoor is running on this port" );
	exit( 0 );
}
if(egrep( pattern: "^220 Bot Server", string: r ) || ContainsString( r, "\xb0\x3e\xc3\x77\x4d\x5a\x90" )){
	service_register( port: port, proto: "agobot.fo" );
	log_message( port: port, data: "An Agobot.fo backdoor is running on this port" );
	exit( 0 );
}
if(ContainsString( r, "RemoteNC Control Password:" )){
	service_register( port: port, proto: "RemoteNC" );
	log_message( port: port, data: "A RemoteNC console is running on this port" );
	exit( 0 );
}
if(ContainsString( r, "Sensor Console Password:" )){
	service_register( port: port, proto: "fluxay" );
	log_message( port: port, data: "A fluxay sensor is running on this port" );
	exit( 0 );
}
if(ContainsString( r, "\x3c\x65\x72\x72\x6f\x72\x3e\x0a" )){
	service_register( port: port, proto: "gkrellmd" );
	log_message( port: port, data: "A gkrellmd system monitor daemon is running on this port" );
	exit( 0 );
}
if(IsMatchRegexp( r, "^[1-9][0-9]*:[KZD]" )){
	service_register( port: port, proto: "QMTP" );
	log_message( port: port, data: "A QMTP / QMQP server is running on this port" );
	exit( 0 );
}
if(IsMatchRegexp( r, "^BZFS" )){
	service_register( port: port, proto: "bzfs" );
	log_message( port: port, data: "A BZFlag game server seems to be running on this port" );
	exit( 0 );
}
if(( ContainsString( r, "SGUIL" ) ) && ereg( pattern: "^SGUIL-[0-9]+\\.[0-9]+\\.[0-9]+ OPENSSL (ENABLED|DISABLED)", string: r )){
	service_register( port: port, proto: "sguil" );
	log_message( port: port, data: "A SGUIL server (Snort Monitoring Console) seems to be running on this port" );
	exit( 0 );
}
if(ereg( pattern: "^Invalid protocol request.*:HHELP.*", string: r )){
	service_register( port: port, proto: "lpd" );
	log_message( port: port, data: "An LPD server seems to be running on this port" );
	exit( 0 );
}
if(strlen( r ) == 4 && ContainsString( r, "\x3d\x15\x1a\x3d" )){
	service_register( port: port, proto: "hacker_defender" );
	log_message( port: port, data: "An 'Hacker Defender' backdoor seems to be running on this port" );
	exit( 0 );
}
if(ContainsString( r, "XPA$ERROR unknown xpans request:" )){
	service_register( port: port, proto: "DS9" );
	log_message( port: port, data: "A DS9 service seems to be running on this port\nSee also : http://hea-www.harvard.edu/RD/ds9/" );
	exit( 0 );
}
if(ContainsString( r, "421 Unauthorized connection to server\n" )){
	service_register( port: port, proto: "ncic" );
	log_message( port: port, data: "A NCIC service seems to be running on this port" );
	exit( 0 );
}
if(strlen( r ) == 4 && ContainsString( r, "\x09\x50\x09\x50" )){
	service_register( port: port, proto: "dell_management_client" );
	log_message( port: port, data: "A Dell Management client seems to be running on this port" );
	exit( 0 );
}
if(ContainsString( r, "gdm already running. Aborting!" )){
	service_register( port: port, proto: "xdmcp" );
	log_message( port: port, data: "An xdmcp server seems to be running on this port" );
	exit( 0 );
}
if(strlen( r ) == strlen( "20040616105304" ) && ereg( pattern: "200[0-9][01][0-9][0-3][0-9][0-2][0-9][0-5][0-9][0-5][0-9]$", string: r )){
	service_register( port: port, proto: "LPTOne" );
	log_message( port: port, data: "A LPTOne server seems to be running on this port" );
	exit( 0 );
}
if(ContainsString( r, "ERROR Not authenticated\n" )){
	service_register( port: port, proto: "hpjfpmd" );
	log_message( port: port, data: "An HP WebJetAdmin server seems to be running on this port" );
	exit( 0 );
}
if(ContainsString( r, "500 P-Error" ) && ContainsString( r, "220 Hello" )){
	service_register( port: port, proto: "unknown_irc_bot" );
	log_message( port: port, data: "An IRC bot seems to be running on this port" );
	exit( 0 );
}
if(ContainsString( r, "220 WinSock" )){
	service_register( port: port, proto: "winsock" );
	log_message( port: port, data: "A WinSock server seems to be running on this port" );
	exit( 0 );
}
if(ContainsString( r, "DeltaUPS:" )){
	service_register( port: port, proto: "delta-ups" );
	log_message( port: port, data: "A DeltaUPS monitoring server seems to be running on this port" );
	exit( 0 );
}
if(ereg( pattern: "lpd: .*", string: r )){
	service_register( port: port, proto: "lpd" );
	log_message( port: port, data: "An LPD server seems to be running on this port" );
	exit( 0 );
}
if(ereg( pattern: "^/usr/sbin/lpd.*", string: r )){
	service_register( port: port, proto: "lpd" );
	log_message( port: port, data: "An LPD server seems to be running on this port" );
	exit( 0 );
}
if(ContainsString( tolower( r ), "<!doctype html" )){
	service_register( port: port, proto: "www" );
	log_message( port: port, data: "A (non-RFC compliant) web server seems to be running on this port" );
	exit( 0 );
}
if(ContainsString( r, "An lpd test connection was completed" ) || ContainsString( r, "Bad from address." ) || ContainsString( r, "your host does not have line printer access" ) || ContainsString( r, "does not have access to remote printer" )){
	service_register( port: port, proto: "lpd" );
	log_message( port: port, data: "An LPD server seems to be running on this port" );
	exit( 0 );
}
if(IsMatchRegexp( r, "^lprsrv: unrecognized command:" )){
	service_register( port: port, proto: "lpd" );
	log_message( port: port, data: "PPR seems to be running on this port" );
	exit( 0 );
}
if(ereg( pattern: "^login: Password: (Login incorrect\\.)?$", string: r ) || ereg( pattern: "^login: Login incorrect\\.", string: r )){
	service_register( port: port, proto: "uucp" );
	log_message( port: port, data: "An UUCP daemon seems to be running on this port" );
	exit( 0 );
}
if(ereg( pattern: "^login: Login incorrect\\.$", string: r )){
	service_register( port: port, proto: "uucp" );
	log_message( port: port, data: "An UUCP daemon seems to be running on this port" );
	exit( 0 );
}
if(ereg( pattern: "^:.* 451 .*:", string: r )){
	service_register( port: port, proto: "irc" );
	log_message( port: port, data: "An IRC server seems to be running on this port" );
	exit( 0 );
}
if(ereg( pattern: "^:matterircd 461 HELP", string: r )){
	set_kb_item( name: "matterircd/detected", value: TRUE );
	service_register( port: port, proto: "irc" );
	log_message( port: port, data: "An IRC (matterircd) server seems to be running on this port" );
	exit( 0 );
}
if(ereg( pattern: "^(Mon|Tue|Wed|Thu|Fri|Sat|Sun|Lun|Mar|Mer|Jeu|Ven|Sam|Dim) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|D[eé]c|F[eé]v|Avr|Mai|Ao[uû]) *(0?[0-9]|[1-3][0-9]) [0-9]+:[0-9]+(:[0-9]+)?( *[ap]m)?( +[A-Z]+)? [1-2][0-9][0-9][0-9].?.?$", string: r ) || ereg( pattern: "^[0-9][0-9] +(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|D[eé]c|F[eé]v|Avr|Mai|Ao[uû]) +[1-2][0-9][0-9][0-9] +[0-9]+:[0-9]+:[0-9]+( *[ap]m)? [A-Z0-9]+.?.?$", string: r, icase: TRUE ) || IsMatchRegexp( r, "^(0?[0-9]|[1-2][0-9]|3[01])-(0[1-9]|1[0-2])-20[0-9][0-9][\r\n]*$" ) || IsMatchRegexp( r, "^([01]?[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9] (19|20)[0-9][0-9]-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])[ \t\r\n]*$" ) || ereg( pattern: "^(Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), (January|February|March|April|May|June|July|August|September|October|November|December) ([0-9]|[1-3][0-9]), [1-2][0-9][0-9][0-9] .*", string: r ) || ereg( pattern: "^[0-9][0-9]?:[0-9][0-9]:[0-9][0-9] [AP]M [0-9][0-9]?/[0-9][0-9]?/[0-2][0-9][0-9][0-9].*$", string: r ) || IsMatchRegexp( r, "^([01]?[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9] +(0?[1-9]|[12][0-9]|3[01])/(0?[1-9]|1[0-2]|3[01])/(19|20)[0-9][0-9][ \t\r\n]*$" ) || IsMatchRegexp( r, "^([01]?[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9] +(0[1-9]|[12][0-9]|3[01])\\.(0[1-9]|1[0-2])\\.(19|20)[0-9][0-9][ \t\r\n]*$" )){
	service_register( port: port, proto: "daytime" );
	log_message( port: port, data: "Daytime is running on this port" );
	exit( 0 );
}
if(match( string: r, pattern: "HP OpenView OmniBack II*" )){
	service_register( port: port, proto: "omniback" );
	log_message( port: port, data: "HP Omniback seems to be running on this port" );
	exit( 0 );
}
if(IsMatchRegexp( r, "^(Micro Focus|HPE?) (OpenView Storage )?Data Protector" )){
	service_register( port: port, proto: "hp_dataprotector", message: "Micro Focus/HP/HPE (OpenView Storage) Data Protector seems to be running on this port" );
	replace_kb_item( name: "hp_dataprotector/" + port + "/banner", value: chomp( r ) );
	log_message( port: port, data: "Micro Focus/HP/HPE (OpenView Storage) Data Protector seems to be running on this port" );
	exit( 0 );
}
if(IsMatchRegexp( r, "^1000 +2\n43\nunexpected message received" ) || ContainsString( r, "gethostbyaddr: No such file or directory" )){
	service_register( port: port, proto: "netbackup" );
	log_message( port: port, data: "Veritas Netbackup seems to be running on this port" );
	exit( 0 );
}
if(r == "\xf6\xff\xff\xff\x10"){
	service_register( port: port, proto: "backup_exec" );
	log_message( port: port, data: "A BackupExec server or Veritas Backup Exec Remote Agent seems to be running on this port" );
	exit( 0 );
}
if(r == "SDPACK"){
	service_register( port: port, proto: "bmc-perf-sd" );
	log_message( port: port, data: "BMC Perform Service Daemon seems to be running on this port" );
	exit( 0 );
}
if(IsMatchRegexp( r, "^220 .* SNPP " ) || egrep( string: r, pattern: "^214 .*PAGE" )){
	service_register( port: port, proto: "snpp" );
	log_message( port: port, data: "A SNPP server seems to be running on this port" );
	exit( 0 );
}
if(egrep( string: r, pattern: "^214-? " ) && ContainsString( r, "MDMFMT" )){
	service_register( port: port, proto: "hylafax-ftp" );
	log_message( port: port, data: "A HylaFax server seems to be running on this port" );
	exit( 0 );
}
if(egrep( string: r, pattern: "^220.*HylaFAX .*Version.*" )){
	service_register( port: port, proto: "hylafax" );
	log_message( port: port, data: "A HylaFax server seems to be running on this port" );
	exit( 0 );
}
if(egrep( string: r, pattern: "^S: FTGate [0-9]+\\.[0-9]+" )){
	service_register( port: port, proto: "ftgate-monitor" );
	log_message( port: port, data: "A FTGate Monitor server seems to be running on this port" );
	exit( 0 );
}
if(strlen( r ) == 2048 && IsMatchRegexp( r, "^[ ,;:.@$#%+HMX\n-]+$" ) && ContainsString( r, "-;;=" ) && ContainsString( r, ".;M####+" ) && ContainsString( r, ".+ .%########" ) && ContainsString( r, ":%.%#########@" )){
	service_register( port: port, proto: "IRCn-finger" );
	log_message( port: port, data: "IRCn finger service seems to be running on this port" );
	exit( 0 );
}
if(ContainsString( r, "Melange Chat Server" )){
	service_register( port: port, proto: "melange-chat" );
	log_message( port: port, data: "Melange Chat Server is running on this port" );
	exit( 0 );
}
if(IsMatchRegexp( r, "^OK Welcome .*DirectUpdate server" )){
	service_register( port: port, proto: "directupdate" );
	log_message( port: port, data: "A DirectUpdate server is running on this port" );
	exit( 0 );
}
if(r == "HELLO XBOX!"){
	service_register( port: port, proto: "xns" );
	log_message( port: port, data: "A XNS streaming server seems to be running on this port" );
	exit( 0 );
}
if(substr( r, 0, 15 ) == hex2raw( s: "4c00000003ff0000ffffffffffffffff" )){
	service_register( port: port, proto: "sap_db_niserver" );
	log_message( port: port, data: "SAP/DB niserver seems to be running on this port" );
	exit( 0 );
}
if(r == "\x01\x09\xD0\x02\xFF\xFF\x01\x03\x12\x4C"){
	service_register( port: port, proto: "db2" );
	log_message( port: port, data: "DB2 is running on this port" );
	exit( 0 );
}
if(ContainsString( r, "Check Point FireWall-1 Client Authentication Server" )){
	service_register( port: port, proto: "fw1_client_auth" );
	log_message( port: port, data: "Checkpoint Firewall-1 Client Authentication Server seems to be running on this port" );
	exit( 0 );
}
if(IsMatchRegexp( r, "^200 .* (PWD Server|poppassd)" )){
	service_register( port: port, proto: "pop3pw" );
	log_message( port: port, data: "A poppassd server seems to be running on this port" );
	exit( 0 );
}
if(ContainsString( r, "Welcome to Ebola " )){
	service_register( port: port, proto: "ebola" );
	set_kb_item( name: "ebola/banner/" + port, value: r );
	log_message( port: port, data: "An Ebola server is running on this port :\\n" + r );
	exit( 0 );
}
if(IsMatchRegexp( r, "^MIDASd v[2-9.]+[a-z]? connection accepted" )){
	service_register( port: port, proto: "midas" );
	log_message( port: port, data: "A MIDAS server is running on this port" );
	exit( 0 );
}
if(IsMatchRegexp( r, "^server [0-9.]+ connections: [0-9]+" ) || IsMatchRegexp( r, "^server [0-9.]+ [0-9a-z.]+ connections: [0-9]+" )){
	service_register( port: port, proto: "crystal" );
	log_message( port: port, data: "Crystal Reports seems to be running on this port" );
	exit( 0 );
}
if(IsMatchRegexp( r, "^TrueWeather\r\n\r\n" )){
	service_register( port: port, proto: "trueweather" );
	log_message( port: port, data: "TrueWeather taskbar applet is running on this port" );
	exit( 0 );
}
if(r == "220 \r\n331 \r\n230 \r\n"){
	service_register( port: port, proto: "ircbot" );
	log_message( port: port, data: "A W32.IRCBot backdoor is running on this port" );
	exit( 0 );
}
if(ereg( string: r, pattern: "^RTSP/1\\.0 " )){
	service_register( port: port, proto: "rtsp" );
	log_message( port: port, data: "A streaming server is running on this port" );
	exit( 0 );
}
if(IsMatchRegexp( r, "^a [0-9a-zA-Z]+GATEWAY [0-9A-Z]+_A [0-9A-Z]+" )){
	service_register( port: port, proto: "ctrlm-ecs-gateway" );
	log_message( port: port, data: "An ECS gateway listener (par of Control-M) is running on this port" );
	exit( 0 );
}
if(r == "\xDE\xAD\xF0\x0D"){
	service_register( port: port, proto: "jwalk" );
	log_message( port: port, data: "A Seagull JWalk server is running on this port" );
	exit( 0 );
}
if(ContainsString( r, "CONEXANT SYSTEMS, INC" ) && ContainsString( r, "ACCESS RUNNER ADSL CONSOLE PORT" ) && ContainsString( r, "LOGON PASSWORD" )){
	service_register( port: port, proto: "conexant-admin" );
	log_message( port: port, data: "Interface of a Conexant ADSL router is running on this port" );
	exit( 0 );
}
if(r == "GET %2F HTTP%2F1.0\n"){
	service_register( port: port, proto: "slimserver" );
	log_message( port: port, data: "The Slimserver streaming server (command interface) is running on this port" );
	exit( 0 );
}
if(ContainsString( r, "Press return:*****************" ) && ContainsString( r, "Enter Password:" )){
	service_register( port: port, proto: "darkshadow-trojan" );
	set_kb_item( name: "trojan/installed/name", value: "darkshadow-trojan" );
	set_kb_item( name: "possible-trojan/installed", value: port );
	exit( 0 );
}
if(r == "ACK"){
	service_register( port: port, proto: "tng-cam" );
	log_message( port: port, data: "CA Messaging (part of Unicenter TNG) is running on this port" );
	exit( 0 );
}
if(ContainsString( r, "+------------------------+" ) || ContainsString( r, "DllTrojan by ScriptGod" )){
	service_register( port: port, proto: "dll-trojan" );
	set_kb_item( name: "trojan/installed/name", value: "dll-trojan" );
	set_kb_item( name: "possible-trojan/installed", value: port );
	exit( 0 );
}
if(r == "\x3d\x15\x1a\x3d"){
	service_register( port: port, proto: "rcserv-trojan" );
	set_kb_item( name: "trojan/installed/name", value: "rcserv-trojan" );
	set_kb_item( name: "possible-trojan/installed", value: port );
	exit( 0 );
}
if(ContainsString( r, "Sifre_Korumasi" ) || ContainsString( r, "000300Dedected burute force atack from your ip adress" ) || ContainsString( r, " Welcom to ProRat Ftp Server" )){
	service_register( port: port, proto: "prorat-trojan" );
	set_kb_item( name: "trojan/installed/name", value: "prorat-trojan" );
	set_kb_item( name: "possible-trojan/installed", value: port );
	exit( 0 );
}
if(r == "ERROR\n"){
	service_register( port: port, proto: "streaming21" );
	log_message( port: port, data: "A Streaming21 server seems to be running on this port" );
	exit( 0 );
}
if(r == "\x01\x01\x00\x08\x1c\xee\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"){
	service_register( port: port, proto: "qsp-proxy" );
	log_message( port: port, data: "A Symantec ManHunt / SNS console (QSP Proxy) seems to be running on this port" );
	exit( 0 );
}
if(ContainsString( r, "ERR/InvalidCommand" )){
	service_register( port: port, proto: "sunraySessionMgr" );
	log_message( port: port, data: "sunraySessionMgr server is running on this port" );
	exit( 0 );
}
if(match( string: r, pattern: "protocolErrorInf error=Missing\\*state=disconnected*" )){
	service_register( port: port, proto: "sunray-utauthd" );
	log_message( port: port, data: "sunray authentication daemon is running on this port" );
	exit( 0 );
}
if(IsMatchRegexp( r, "^ICY 401" )){
	service_register( port: port, proto: "shoutcast" );
	log_message( port: port, data: "A shoutcast server seems to be running on this port" );
	exit( 0 );
}
if(egrep( pattern: "^Getserver 1\\.0 - identify yourself", string: r )){
	service_register( port: port, proto: "nfr-admin-gui" );
	log_message( port: port, data: "An NFR Administrative interface is listening on this port" );
	exit( 0 );
}
if(ContainsString( r, "ERROR: unknown directive: " )){
	service_register( port: port, proto: "remstats" );
	log_message( port: port, data: "A remstats service is running on this port" );
	exit( 0 );
}
if(ContainsString( r, "NCD X Terminal Configuration" )){
	service_register( port: port, proto: "ncdx_term_config" );
	log_message( port: port, data: "A NCD X Terminal Configuration service is running on this port" );
	exit( 0 );
}
if(ContainsString( r, "NPC Telnet permit one" )){
	service_register( port: port, proto: "telnet" );
	log_message( port: port, data: "A (NPC) telnet service is running on this port" );
	exit( 0 );
}
if(ContainsString( r, "SiteManager Proxy" )){
	service_register( port: port, proto: "site_manager_proxy" );
	log_message( port: port, data: "A Site Manager Proxy service is running on this port" );
	exit( 0 );
}
if(egrep( pattern: "^GPSD,.*", string: r )){
	service_register( port: port, proto: "gpsd" );
	log_message( port: port, data: "A gpsd daemon is running on this port" );
	exit( 0 );
}
if(egrep( pattern: "^200.*Citadel(/UX| server ready).*", string: r )){
	service_register( port: port, proto: "citadel/ux" );
	log_message( port: port, data: "A Citadel/UX BBS is running on this port" );
	exit( 0 );
}
if(ContainsString( r, "Gnome Batalla" )){
	service_register( port: port, proto: "gnome_batalla" );
	log_message( port: port, data: "A Gnome Batalla service is running on this port" );
	exit( 0 );
}
if(ContainsString( r, "System Status" ) && ContainsString( r, "Uptime" )){
	service_register( port: port, proto: "systat" );
	log_message( port: port, data: "The systat service is running on this port" );
	exit( 0 );
}
if(ContainsString( r, "ESTABLISHED" ) && ContainsString( r, "TCP" )){
	service_register( port: port, proto: "netstat" );
	log_message( port: port, data: "The netstat service is running on this port" );
	exit( 0 );
}
if(IsMatchRegexp( r, " (A\\. A\\. Milne|Albert Einstein|Anonimo|Antico proverbio cinese|Autor desconocido|Charles Dickens|Francisco de Quevedo y Villegas|George Bernard Shaw|Jaime Balmes|Johann Wolfgang von Goethe|Jil Sander|Juana de Asbaje|Konfucius|Lord Philip Chesterfield|Montaigne|Petrarca|Ralph Waldo Emerson|Seneca|Syrus|Werner von Siemens)" ) || IsMatchRegexp( r, "\\((Albert Einstein|Anatole France|August von Kotzebue|Berthold Brecht|Bertrand Russell|Federico Fellini|Fritz Muliar|Helen Markel|Mark Twain|Oscar Wilde|Tschechisches Sprichwort|Schweizer Sprichwort|Volksweisheit)\\)" ) || ContainsString( r, "(Juliette Gr" ) || ContainsString( r, "Dante (Inferno)" ) || ContainsString( r, "Semel in anno licet insanire." ) || ContainsString( r, "Oh the nerves, the nerves; the mysteries of this machine called man" ) || ContainsString( r, "Metastasio (Ipermestra)" ) || ContainsString( r, "\"\r\nAnonimo" ) || IsMatchRegexp( r, "^\"[^\"]+\" *Autor desconocido[ \t\r\n]*$" )){
	replace_kb_item( name: "qotd/tcp/" + port + "/banner", value: chomp( r ) );
	service_register( port: port, proto: "qotd" );
	log_message( port: port, data: "A qotd (Quote of the Day) service seems to be running on this port." );
	exit( 0 );
}
if(ContainsString( r, "/usr/games/fortune: not found" )){
	replace_kb_item( name: "qotd/tcp/" + port + "/banner", value: chomp( r ) );
	service_register( port: port, proto: "qotd" );
	log_message( port: port, data: "A qotd (Quote of the Day) service seems to be running on this port (misconfigured)." );
	exit( 0 );
}
if(ContainsString( r, "Can't locate loadable object for module" ) && ContainsString( r, "BEGIN failed--compilation aborted" )){
	service_register( port: port, proto: "broken-perl-script" );
	log_message( port: port, data: "A broken perl script is running on this port" );
	exit( 0 );
}
if(ContainsString( r, "Check Point FireWall-1 authenticated Telnet server" )){
	service_register( port: port, proto: "fw1-telnet-auth" );
	log_message( port: port, data: "A Firewall-1 authenticated telnet server is running on this port" );
	exit( 0 );
}
if(ContainsString( r, "NOTICE AUTH : Bitlbee" ) || ContainsString( r, "NOTICE AUTH :BitlBee-IRCd initialized" )){
	service_register( port: port, proto: "irc" );
	log_message( port: port, data: "An IRC server seems to be running on this port" );
	exit( 0 );
}
if(IsMatchRegexp( r, "^ERROR :Closing Link:.*Throttled: Reconnecting too fast" ) || IsMatchRegexp( r, "^:.*NOTICE (Auth|AUTH).*Looking up your hostname" )){
	service_register( port: port, proto: "irc" );
	log_message( port: port, data: "An IRC server seems to be running on this port" );
	exit( 0 );
}
if(r == "ERROR: Your host is trying to (re)connect too fast -- throttled\n" || r == "ERROR :Trying to reconnect too fast.\n"){
	service_register( port: port, proto: "irc" );
	log_message( port: port, data: "An IRC server might be running on this port" );
	exit( 0 );
}
if(IsMatchRegexp( r, "^sh-[0-9.]+# " )){
	service_register( port: port, proto: "wild_shell" );
	set_kb_item( name: "possible/backdoor", value: port );
	set_kb_item( name: "backdoor/name", value: "wild_shell" );
	exit( 0 );
}
if(( ContainsString( r, "Microsoft Windows [Version " ) ) && ( ContainsString( r, "(C) Copyright 1985-" ) ) && ( ContainsString( r, "Microsoft Corp." ) )){
	service_register( port: port, proto: "wild_shell" );
	set_kb_item( name: "possible/backdoor", value: port );
	set_kb_item( name: "backdoor/name", value: "wild_shell" );
	exit( 0 );
}
if(ContainsString( r, "1|0|0||" )){
	service_register( port: port, proto: "PigeonServer" );
	log_message( port: port, data: "PigeonServer seems to be running on this port" );
	exit( 0 );
}
if(IsMatchRegexp( r, "^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+\n$" )){
	service_register( port: port, proto: "kde-lisa" );
	log_message( port: port, data: "KDE Lisa server is running on this port" );
	exit( 0 );
}
if(r == "ZBX_NOTSUPPORTED\n" || ( IsMatchRegexp( r, "^ZBXD" ) && ContainsString( r, "ZBX_NOTSUPPORTED" ) )){
	service_register( port: port, proto: "zabbix" );
	log_message( port: port, data: "A Zabbix Agent is running on this port" );
	exit( 0 );
}
if(r == "3 --6 Bad request. \r\n.\r\n"){
	service_register( port: port, proto: "gopher" );
	log_message( port: port, data: "A Gopher server seems to be running on this port" );
	exit( 0 );
}
if(match( string: r, pattern: "\x01rlogind: Permission denied*", icase: TRUE )){
	service_register( port: port, proto: "rlogin" );
	log_message( port: port, data: "rlogind seems to be running on this port" );
	exit( 0 );
}
if(match( string: r, pattern: "statd version:*msgid:*" )){
	service_register( port: port, proto: "nagios-statd" );
	log_message( port: port, data: "nagios-statd seems to be running on this port" );
	exit( 0 );
}
if(match( string: r, pattern: "The smbridge is used by*" )){
	service_register( port: port, proto: "smbridge" );
	log_message( port: port, data: "IBM OSA SMBridge seems to be running on this port" );
	exit( 0 );
}
if(match( string: r, pattern: "<?xml version=*" ) && ContainsString( r, " GANGLIA_XML " ) && ContainsString( r, "ATTLIST HOST GMOND_STARTED" )){
	service_register( port: port, proto: "gmond" );
	log_message( port: port, data: "Ganglia monitoring daemon seems to be running on this port" );
	exit( 0 );
}
if(match( string: r, pattern: "Natural MicroSystem CTAccess Server *" )){
	service_register( port: port, proto: "ctaccess" );
	log_message( port: port, data: "Natural MicroSystem CTAccess Server is running on this port" );
	exit( 0 );
}
if(r == "\x2f\x44\x94\x72"){
	service_register( port: port, proto: "spysweeper" );
	log_message( port: port, data: "Spy Sweeper Enterprise client seems to be running on this port" );
	exit( 0 );
}
if(IsMatchRegexp( r, "^\r\nEfficient [0-9]+ DMT Roter .* Ready.*Login:" )){
	service_register( port: port, proto: "efficient-router" );
	log_message( port: port, data: "An Efficient router administration interface is running on this port" );
	exit( 0 );
}
if(match( string: r, pattern: "KLUG\0*IP-SwA V*\0\0\0\0*" )){
	service_register( port: port, proto: "hg-gate" );
	log_message( port: port, data: "A HG gate for IP phones is running on this port" );
	exit( 0 );
}
if(match( string: r, pattern: "220 Axis Developer Board*ready*503 Bad sequence*" )){
	service_report( port: port, svc: "axis-developer-board" );
	exit( 0 );
}
if(substr( r, 0, 5 ) == "hosts/"){
	v = split( buffer: substr( r, 6 ), sep: "\n", keep: FALSE );
	if(max_index( v ) == 2){
		service_register( port: port, proto: "ibm-pssp-spseccfg" );
		rep = "IBM PSSP spseccfg is running on this port.\n";
		if( strlen( v[0] ) > 0 ) {
			rep = strcat( rep, "It reports that the DCE hostname is \"", v[0], "\".\n" );
		}
		else {
			rep += "DCE is not configured on this host\n";
		}
		rep = strcat( rep, "The system partition name or the local hostname is \"", v[1], "\"." );
		log_message( port: port, data: rep );
		exit( 0 );
	}
}
if(r == "ERR password required\r\n" && rget == "ERR password required\r\nERR password required\r\n"){
	service_register( port: port, proto: "fli4l-imonc" );
	log_message( port: port, data: "imonc might be running on this port" );
	exit( 0 );
}
if(r == "\x06\x00\x00\x00\x00\x00\x1a\x00\x00\x00"){
	service_register( port: port, proto: "mldonkey-gui" );
	log_message( port: port, data: "MLDonkey is running on this port (GUI access)" );
	exit( 0 );
}
func report_and_exit( port, data ){
	log_message( port: port, data: data );
	exit( 0 );
}
if(r == "HELP\r\n\r\n"){
	service_register( port: port, proto: "echo" );
	report_and_exit( port: port, data: "Echo \"simple TCP/IP service\" is running on this port" );
}
if(IsMatchRegexp( r, "^SPAMD/[0-9.]+ [0-9]+ Bad header line:" )){
	service_register( port: port, proto: "spamd" );
	report_and_exit( port: port, data: "A SpamAssassin daemon is running on this port" );
}
if(strlen( r ) > 3 && ord( r[0] ) == 5 && ord( r[1] ) <= 8 && ord( r[2] ) == 0 && ord( r[3] ) <= 4){
	service_register( port: port, proto: "socks5" );
	report_and_exit( port: port, data: "A SOCKS5 server seems to be running on this port" );
}
if(strlen( r ) > 1 && ord( r[0] ) == 0 && ord( r[1] ) >= 90 && ord( r[1] ) <= 93){
	service_register( port: port, proto: "socks4" );
	report_and_exit( port: port, data: "A SOCKS4 server seems to be running on this port" );
}
if( egrep( pattern: "^\\+OK.*POP2.*", string: r, icase: TRUE ) ){
	service_register( port: port, proto: "pop2" );
	report_and_exit( port: port, data: "A POP2 server seems to be running on this port" );
}
else {
	if(egrep( pattern: "^\\+OK.*POP.*", string: r, icase: TRUE ) || egrep( pattern: "^\\+OK.*Dovecot.*ready.", string: r, icase: TRUE )){
		service_register( port: port, proto: "pop3" );
		report_and_exit( port: port, data: "A POP3 server seems to be running on this port" );
	}
}
if(egrep( pattern: "^220 .*FTP", string: r, icase: TRUE ) || egrep( pattern: "^214-? .*FTP", string: r, icase: TRUE ) || egrep( pattern: "^220 .*CrownNet", string: r, icase: TRUE ) || ( egrep( pattern: "^220 ", string: r ) && egrep( pattern: "^530 Please login with USER and PASS", string: r, icase: TRUE ) )){
	banner = egrep( pattern: "^2[01][04]-? ", string: r );
	if(banner){
		set_kb_item( name: "ftp/banner/" + port, value: banner );
	}
	service_register( port: port, proto: "ftp" );
	report_and_exit( port: port, data: "A FTP server seems to be running on this port" );
}
if(egrep( pattern: "^220( |-).*(SMTP|mail)", string: r, icase: TRUE ) || egrep( pattern: "^214-? .*(HELO|MAIL|RCPT|DATA|VRFY|EXPN)", string: r ) || egrep( pattern: "^220-? .*OpenVMS.*ready", string: r ) || egrep( pattern: "^421-? .*SMTP", string: r )){
	service_register( port: port, proto: "smtp" );
	report_and_exit( port: port, data: "A SMTP server seems to be running on this port" );
}
if(egrep( pattern: "^20[01] .*(NNTP|NNRP)", string: r ) || egrep( pattern: "^100 .*commands", string: r, icase: TRUE )){
	banner = egrep( pattern: "^200 ", string: r );
	if(banner){
		set_kb_item( name: "nntp/banner/" + port, value: chomp( banner ) );
	}
	service_register( port: port, proto: "nntp" );
	report_and_exit( port: port, data: "A NNTP server seems to be running on this port" );
}
if(egrep( pattern: "^SSH-", string: r )){
	service_register( port: port, proto: "ssh" );
	report_and_exit( port: port, data: "A SSH server seems to be running on this port" );
}
if(ContainsString( r, "Destination server does not have Ssh activated" )){
	service_register( port: port, proto: "disabled-ssh" );
	report_and_exit( port: port, data: "A disabled SSH service seems to be running on this port" );
}
if(egrep( string: r, pattern: "^0 *, *0 *: * ERROR *:" )){
	service_register( port: port, proto: "auth" );
	report_and_exit( port: port, data: "An Auth/ident server seems to be running on this port" );
}
if(( egrep( string: r, pattern: "HELP: no such user", icase: TRUE ) ) || ( egrep( string: r, pattern: ".*Line.*User.*Host", icase: TRUE ) ) || ( egrep( string: r, pattern: ".*Login.*Name.*TTY", icase: TRUE ) ) || ContainsString( r, "?Sorry, could not find \"GET\"" ) || ContainsString( r, "Login name: HELP" ) || ( ( ContainsString( r, "Time Since Boot:" ) ) && ( ContainsString( r, "Name        pid" ) ) )){
	service_register( port: port, proto: "finger" );
	report_and_exit( port: port, data: "A finger server seems to be running on this port" );
}
if(( ContainsString( r, "501 Method Not Implemented" ) ) || ( ereg( string: r, pattern: "^HTTP/1\\.[01]" ) ) || ContainsString( r, "action requested by the browser" )){
	service_register( port: port, proto: "www" );
	report_and_exit( port: port, data: "A web server seems to be running on this port" );
}
if(IsMatchRegexp( r, "^BitTorrent protocol" )){
	service_register( port: port, proto: "BitTorrent" );
	report_and_exit( port: port, data: "A BitTorrent server seems to be running on this port" );
}
if(match( string: r, pattern: "<stream:stream xmlns:stream='http://etherx.jabber.org/streams'*</stream:stream>", icase: TRUE ) || ContainsString( r, "<stream:error>Invalid XML</stream:error>" ) || ContainsString( r, "<stream:error>Connection is closing</stream:error></stream:stream>" )){
	service_register( port: port, proto: "jabber" );
	report_and_exit( port: port, data: "A jabber server seems to be running on this port" );
}
if(ContainsString( r, "Hello, this is zebra " )){
	service_register( port: port, proto: "zebra" );
	set_kb_item( name: "zebra/banner/" + port, value: r );
	cpe = build_cpe( value: r, exp: "^([0-9.]+([a-z])?)", base: "cpe:/a:gnu:zebra:" );
	if(!isnull( cpe )){
		register_host_detail( name: "App", value: cpe );
	}
	report_and_exit( port: port, data: "A zebra daemon is running on this port" );
}
if(egrep( pattern: "^\\* *OK .* IMAP", string: r ) || egrep( pattern: "^\\* *OK IMAP", string: r ) || egrep( pattern: "^\\* *OK .* cimap", string: r ) || egrep( pattern: "^\\* ?ok iplanet messaging multiplexor", string: r, icase: TRUE ) || egrep( pattern: "^\\* ?ok communigate pro imap server", string: r, icase: TRUE ) || egrep( pattern: "^\\* ok courier-imap", string: r, icase: TRUE )){
	service_register( port: port, proto: "imap" );
	report_and_exit( port: port, data: "An IMAP server is running on this port" );
}
if(ContainsString( r, "cvs [pserver]" )){
	service_register( port: port, proto: "cvspserver" );
	report_and_exit( port: port, data: "A CVS pserver is running on this port" );
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
	service_register( port: port, proto: "chargen" );
	report_and_exit( port: port, data: "A chargen server is running on this port" );
}
if(egrep( pattern: ":Welcome!.*NOTICE.*psyBNC", icase: TRUE, string: r )){
	service_register( port: port, proto: "psyBNC" );
	report_and_exit( port: port, data: "psyBNC seems to be running on this port" );
}
if(ContainsString( r, "CCProxy Telnet Service Ready" )){
	service_register( port: port, proto: "ccproxy-telnet" );
	log_message( port: port, data: "CCProxy (telnet) seems to be running on this port" );
	exit( 0 );
}
if(ContainsString( r, "CCProxy FTP Service" )){
	service_register( port: port, proto: "ccproxy-ftp" );
	log_message( port: port, data: "CCProxy (ftp) seems to be running on this port" );
	exit( 0 );
}
if(ContainsString( r, "CCProxy " ) && ContainsString( r, "SMTP Service Ready" )){
	service_register( port: port, proto: "ccproxy-smtp" );
	log_message( port: port, data: "CCProxy (smtp) seems to be running on this port" );
	exit( 0 );
}
if(ContainsString( r, "CMailServer " ) && ContainsString( r, "SMTP Service Ready" )){
	service_register( port: port, proto: "cmailserver-smtp" );
	log_message( port: port, data: "CMailServer (smtp) seems to be running on this port" );
	exit( 0 );
}
if(( IsMatchRegexp( r, "^\x30\x11\x00\x00\x00\x00\x00\x00" ) ) && ( strlen( r ) == 40 )){
	service_register( port: port, proto: "dameware" );
	log_message( port: port, data: "Dameware seems to be running on this port" );
	exit( 0 );
}
if(ContainsString( r, "Cirrato Client" )){
	service_register( port: port, proto: "cirrato" );
	report_and_exit( port: port, data: "Cirrato Client seems to be running on this port." );
}
if(ContainsString( r, "501 \"Invalid command\"" ) && ereg( pattern: "^[0-9][0-9][0-9].+MailSite Mail Management Server .+ ready", string: r )){
	service_register( port: port, proto: "mailma" );
	report_and_exit( port: port, data: "MailSite's Mail Management Agent (MAILMA) seems to be running on this port." );
}
if(egrep( pattern: "^[0-9][0-9][0-9][0-9]-NMAP \\$Revision: .+Help", string: r )){
	service_register( port: port, proto: "novell_nmap" );
	log_message( port: port, data: "A Novell Network Messaging Application Protocol (NMAP) agent seems to be running on this port" );
	exit( 0 );
}
if(ContainsString( r, "Open DC Hub, version" ) && ContainsString( r, "administrators port" )){
	service_register( port: port, proto: "opendchub" );
	log_message( port: port, data: "Open DC Hub Administrative interface (peer-to-peer) seems to be running on this port" );
	exit( 0 );
}
if(ereg( pattern: "^$MyNick ", string: r )){
	service_register( port: port, proto: "DirectConnect" );
	log_message( port: port, data: "Direct Connect seems to be running on this port" );
	exit( 0 );
}
if(ereg( pattern: "^RFB [0-9]", string: r )){
	service_register( port: port, proto: "vnc" );
	replace_kb_item( name: "vnc/banner/" + port, value: r );
	log_message( port: port, data: "A VNC server seems to be running on this port" );
	exit( 0 );
}
if(egrep( pattern: "^BZFS00", string: r )){
	service_register( port: port, proto: "bzFlag" );
	log_message( port: port, data: "A bzFlag server seems to be running on this port" );
	exit( 0 );
}
if(strlen( r ) == 3 && ( r[2] == "\x10" || r[2] == "\x0b" ) || r == "\x78\x01\x07" || r == "\x10\x73\x0A" || r == "\x78\x01\x07" || r == "\x08\x40\x0c"){
	service_register( port: port, proto: "msdtc" );
	log_message( port: port, data: "A MSDTC server seems to be running on this port" );
	exit( 0 );
}
if(ContainsString( r, "Welcome to the TeamSpeak 3 ServerQuery interface" )){
	service_register( port: port, proto: "teamspeak-serverquery" );
	report_and_exit( port: port, data: "A Teamspeak 3 ServerQuery interface seems to be running on this port." );
}
if(ContainsString( r, "[TS]" )){
	service_register( port: port, proto: "teamspeak-tcpquery" );
	report_and_exit( port: port, data: "A Teamspeak 2 Query interface seems to be running on this port." );
}
if(r == "GIOP\x01"){
	service_register( port: port, proto: "giop" );
	log_message( port: port, data: "A GIOP-enabled service is running on this port" );
	exit( 0 );
}
if(match( string: r, pattern: "\"IMPLEMENTATION\" \"Cyrus timsieved v*\"*\"SASL\"*" )){
	service_register( port: port, proto: "sieve" );
	log_message( port: port, data: "Sieve mail filter daemon seems to be running on this port" );
	exit( 0 );
}
if(ContainsString( r, "IODETTE FTP READY" )){
	service_register( port: port, proto: "odette-ftp" );
	report_and_exit( port: port, data: "A service providing a ODETTE File Transfer Protocol seems to be running on this port." );
}
if(ContainsString( r, "(Thread" ) && ( ContainsString( r, "Notify Wlan Link " ) || ContainsString( r, "Notify Eth Link " ) || ContainsString( r, "Received unknown command on socket" ) || ContainsString( r, "fsfsFlashFileHandleOpen" ) || ContainsString( r, "Found existing handle " ) || ContainsString( r, "After waiting approx. " ) || ContainsString( r, "Timer fired at " ) || ContainsString( r, "ControlSocketServerInstructClientToLeave" ) || ( ContainsString( r, "WFSAPI" ) && ContainsString( r, "File not found" ) ) )){
	service_register( port: port, proto: "wifiradio-setup", message: "A WiFi radio setup service seems to be running on this port." );
	log_message( port: port, data: "A WiFi radio setup service seems to be running on this port." );
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
if(IsMatchRegexp( rhexstr, "^5[19]000000$" )){
	service_register( port: port, proto: "fw1-topology", message: "A Check Point FireWall-1 (FW-1) SecureRemote (SecuRemote) service seems to be running on this port" );
	log_message( port: port, data: "A Check Point FireWall-1 (FW-1) SecureRemote (SecuRemote) service seems to be running on this port" );
	exit( 0 );
}
if(IsMatchRegexp( rhexstr, "^15030[0-3]00020[1-2]..$" ) || IsMatchRegexp( rhexstr, "^1500000732$" ) || IsMatchRegexp( rhexstr, "^150301$" )){
	service_register( port: port, proto: "ssl", message: "A service responding with an SSL/TLS alert seems to be running on this port." );
	log_message( port: port, data: "A service responding with an SSL/TLS alert seems to be running on this port." );
	exit( 0 );
}
if(IsMatchRegexp( r, "^\"[^\"]+\"[ \t\r\n]+[A-Za-z -]+[ \t\r\n]+\\([0-9]+(-[0-9]+)?\\)[ \t\r\n]+$" ) || egrep( pattern: "^[A-Za-z. -]+\\([0-9-]+\\)", string: r )){
	replace_kb_item( name: "qotd/tcp/" + port + "/banner", value: chomp( banner ) );
	service_register( port: port, proto: "qotd" );
	log_message( port: port, data: "A qotd (Quote of the Day) service seems to be running on this port." );
	exit( 0 );
}
if(!r0){
	unknown_banner_set( port: port, banner: r );
}

