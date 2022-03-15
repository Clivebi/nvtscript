if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108747" );
	script_version( "2021-06-18T09:47:07+0000" );
	script_tag( name: "last_modification", value: "2021-06-18 09:47:07 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2020-04-14 11:32:00 +0000 (Tue, 14 Apr 2020)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Service Detection from 'spontaneous' Banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Service detection" );
	script_dependencies( "find_service.sc" );
	script_require_ports( "Services/unknown" );
	script_tag( name: "summary", value: "This plugin performs service detection.

  This plugin is a complement of find_service.nasl. It evaluates 'spontaneous' banners
  sent by the remaining unknown services and tries to identify them." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
require("ssh_func.inc.sc");
if(!port = get_kb_item( "Services/unknown" )){
	exit( 0 );
}
if(!get_port_state( port )){
	exit( 0 );
}
if(!service_is_unknown( port: port )){
	exit( 0 );
}
key = "FindService/tcp/" + port + "/spontaneous";
banner = get_kb_item( key );
if( strlen( banner ) <= 0 ){
	soc = open_sock_tcp( port );
	if(!soc){
		exit( 0 );
	}
	banner = recv_line( socket: soc, length: 4096 );
	close( soc );
	if(strlen( banner ) > 0){
		set_kb_item( name: key, value: banner );
		bannerhex = hexstr( banner );
		if(ContainsString( banner, "\0" )){
			set_kb_item( name: key + "Hex", value: bannerhex );
		}
	}
}
else {
	bannerhex = hexstr( banner );
}
if(strlen( banner ) <= 0){
	exit( 0 );
}
if(IsMatchRegexp( banner, "^[0-9]+ *, *[0-9]+ *: *USERID *: *UNIX *: *[a-z0-9]+" )){
	service_register( port: port, proto: "fake-identd" );
	set_kb_item( name: "fake_identd/" + port, value: TRUE );
	exit( 0 );
}
if(match( string: banner, pattern: "<?xml version=*" ) && ContainsString( banner, " GANGLIA_XML " ) && ContainsString( banner, "ATTLIST HOST GMOND_STARTED" )){
	service_register( port: port, proto: "gmond" );
	log_message( port: port, data: "Ganglia monitoring daemon seems to be running on this port" );
	exit( 0 );
}
if(match( string: banner, pattern: "CIMD2-A ConnectionInfo: SessionId = * PortId = *Time = * AccessType = TCPIP_SOCKET PIN = *" )){
	service_report( port: port, svc: "smsc" );
	exit( 0 );
}
if(ereg( pattern: "^(Mon|Tue|Wed|Thu|Fri|Sat|Sun|Lun|Mar|Mer|Jeu|Ven|Sam|Dim) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|D[eé]c|F[eé]v|Avr|Mai|Ao[uû]) *(0?[0-9]|[1-3][0-9]) [0-9]+:[0-9]+(:[0-9]+)?( *[ap]m)?( +[A-Z]+)? [1-2][0-9][0-9][0-9].?.?$", string: banner )){
	service_report( port: port, svc: "daytime" );
	exit( 0 );
}
if(IsMatchRegexp( banner, "^(\\|/dev/[a-z0-9/-]+\\|[^|]*\\|[^|]*\\|[^|]\\|)+$" )){
	service_report( port: port, svc: "hddtemp" );
	exit( 0 );
}
if(match( string: banner, pattern: "220 *FTP Server ready\r\n", icase: TRUE ) || match( string: banner, pattern: "220 *FTP Server ready.\r\n", icase: TRUE )){
	service_report( port: port, svc: "ftp" );
	exit( 0 );
}
if(match( string: banner, pattern: "\"IMPLEMENTATION\" \"Cyrus timsieved v*\"*\"SASL\"*" )){
	service_register( port: port, proto: "sieve", message: "Sieve mail filter daemon seems to be running on this port." );
	log_message( port: port, data: "Sieve mail filter daemon seems to be running on this port." );
	exit( 0 );
}
if(match( string: banner, pattern: "220 Axis Developer Board*" )){
	service_report( port: port, svc: "axis-developer-board" );
	exit( 0 );
}
if(match( string: banner, pattern: "  \x5f\x5f\x5f           *Copyright (C) * Eggheads Development Team" )){
	service_report( port: port, svc: "eggdrop" );
	exit( 0 );
}
if(ereg( string: banner, pattern: "^OK MPD [0-9.]+\n" )){
	service_report( port: port, svc: "mpd" );
	exit( 0 );
}
if(egrep( pattern: "^OK WorkgroupShare.+server ready", string: banner, icase: FALSE )){
	replace_kb_item( name: "workgroupshare/" + port + "/banner", value: chomp( banner ) );
	service_report( port: port, svc: "WorkgroupShare" );
	exit( 0 );
}
if(ContainsString( banner, "* Eudora-SET (IMPLEMENTATION Eudora Internet Mail Server" )){
	service_report( port: port, svc: "acap" );
	exit( 0 );
}
if(ContainsString( banner, "IOR:010000002600000049444c3a536f70686f734d6573736167696e672f4d657373616765526f75746572" )){
	service_register( port: port, proto: "sophos_rms", message: "A Sophos Remote Messaging / Management Server seems to be running on this port." );
	log_message( port: port, data: "A Sophos Remote Messaging / Management Server seems to be running on this port." );
	exit( 0 );
}
if(IsMatchRegexp( banner, "^\\* *BYE " )){
	service_report( port: port, svc: "imap", banner: banner, message: "The IMAP server rejects connection from our host. We cannot test it." );
	log_message( port: port, data: "The IMAP server rejects connection from our host. We cannot test it." );
	exit( 0 );
}
if(match( string: banner, pattern: "200 CommuniGatePro PWD Server * ready*" )){
	service_report( port: port, svc: "pop3pw" );
	exit( 0 );
}
if(IsMatchRegexp( banner, "^RFB [0-9]" )){
	service_report( port: port, svc: "vnc" );
	replace_kb_item( name: "vnc/banner/" + port, value: banner );
	exit( 0 );
}
if(( IsMatchRegexp( banner, "^RPY [0-9] [0-9]" ) && ContainsString( banner, "Content-Type: application/" ) ) || ( ContainsString( banner, "<profile uri=" ) && ContainsString( banner, "http://iana.org/beep/" ) ) || ContainsString( banner, "Content-Type: application/beep" )){
	service_register( port: port, proto: "beep", message: "A service supporting the Blocks Extensible Exchange Protocol (BEEP) seems to be running on this port." );
	log_message( port: port, data: "A service supporting the Blocks Extensible Exchange Protocol (BEEP) seems to be running on this port." );
	exit( 0 );
}
if(ssh_verify_server_ident( data: banner )){
	service_register( port: port, proto: "ssh", message: "A SSH service seems to be running on this port." );
	log_message( port: port, data: "A SSH service seems to be running on this port." );
	replace_kb_item( name: "SSH/server_banner/" + port, value: chomp( banner ) );
}
if(IsMatchRegexp( bannerhex, "^ACED....(.+|$)" )){
	service_register( port: port, proto: "java-rmi", message: "A Java RMI service seems to be running on this port." );
	log_message( port: port, data: "A Java RMI service seems to be running on this port." );
}
if(IsMatchRegexp( banner, "^\"[^\"]+\"[ \t\r\n]+[A-Za-z -]+[ \t\r\n]+\\([0-9]+(-[0-9]+)?\\)[ \t\r\n]+$" )){
	replace_kb_item( name: "qotd/tcp/" + port + "/banner", value: chomp( banner ) );
	service_register( port: port, proto: "qotd", message: "A qotd (Quote of the Day) service seems to be running on this port." );
	log_message( port: port, data: "A qotd (Quote of the Day) service qotd seems to be running on this port." );
	exit( 0 );
}
exit( 0 );

