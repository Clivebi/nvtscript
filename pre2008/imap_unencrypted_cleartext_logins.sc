if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15856" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "4.8" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:P/I:P/A:N" );
	script_xref( name: "OSVDB", value: "3119" );
	script_name( "IMAP Unencrypted Cleartext Login" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 George A. Theall" );
	script_family( "General" );
	script_dependencies( "imap4_banner.sc", "gb_starttls_imap.sc", "logins.sc" );
	script_require_ports( "Services/imap", 143 );
	script_mandatory_keys( "imap/banner/available" );
	script_xref( name: "URL", value: "http://www.ietf.org/rfc/rfc2222.txt" );
	script_xref( name: "URL", value: "http://www.ietf.org/rfc/rfc2595.txt" );
	script_tag( name: "solution", value: "Configure the remote server to always enforce encrypted connections via
  SSL/TLS with the 'STARTTLS' command." );
	script_tag( name: "summary", value: "The remote host is running an IMAP daemon that allows cleartext logins over
  unencrypted connections.

  NOTE: Valid credentials needs to given to the settings of 'Login configurations' OID: 1.3.6.1.4.1.25623.1.0.10870." );
	script_tag( name: "impact", value: "An attacker can uncover user names and passwords by sniffing traffic to the IMAP
  daemon if a less secure authentication mechanism (eg, LOGIN command, AUTH=PLAIN, AUTH=LOGIN) is used." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("imap_func.inc.sc");
port = imap_get_port( default: 143 );
encaps = get_port_transport( port );
if(encaps > ENCAPS_IP){
	exit( 0 );
}
banner = imap_get_banner( port: port );
if(!banner){
	exit( 0 );
}
if(get_kb_item( "imap/" + port + "/starttls" )){
	STARTTLS = TRUE;
}
pat = "\\[CAPABILITY ([^]]+)";
capas = egrep( string: banner, pattern: pat, icase: TRUE );
capas = chomp( capas );
if(capas){
	caps = eregmatch( string: capas, pattern: pat, icase: TRUE );
	if(caps[1]){
		capalist = split( buffer: caps[1], sep: " ", keep: FALSE );
		capalist = sort( capalist );
	}
}
if(!capalist || !is_array( capalist )){
	capalist = get_kb_list( "imap/fingerprints/" + port + "/nontls_capalist" );
}
done = FALSE;
if(capalist && is_array( capalist )){
	for capa in capalist {
		if(capa == "IMAP4rev1"){
			continue;
		}
		if(egrep( string: capa, pattern: "^AUTH=(PLAIN|LOGIN)", icase: FALSE )){
			VULN = TRUE;
			report += "\n" + capa;
		}
		if(egrep( string: capa, pattern: "^LOGINDISABLED", icase: FALSE )){
			break;
		}
	}
	done = TRUE;
}
if(VULN){
	report = "The remote IMAP server accepts logins via the following cleartext authentication mechanisms over unencrypted connections:\n" + report;
	if(STARTTLS){
		report += "\n\nThe remote IMAP server supports the \'STARTTLS\' command but isn\'t enforcing the use of it for the cleartext authentication mechanisms.";
	}
	security_message( port: port, data: report );
	exit( 0 );
}
if(done){
	exit( 99 );
}
if(!done){
	kb_creds = imap_get_kb_creds();
	user = kb_creds["login"];
	pass = kb_creds["pass"];
	if(!user || !pass){
		exit( 0 );
	}
	soc = imap_open_socket( port );
	if(!soc){
		exit( 0 );
	}
	++tag;
	c = NASLString( "a", NASLString( tag ), " AUTHENTICATE \"PLAIN\"" );
	send( socket: soc, data: NASLString( c, "\\r\\n" ) );
	s = recv_line( socket: soc, length: 1024 );
	s = chomp( s );
	if(IsMatchRegexp( s, "^\\+" )){
		c = base64( str: raw_string( 0, user, 0, pass ) );
		send( socket: soc, data: NASLString( c, "\\r\\n" ) );
		n = 0;
		for(;s = recv_line( socket: soc, length: 1024 );){
			n++;
			s = chomp( s );
			m = eregmatch( pattern: NASLString( "^a", NASLString( tag ), " (OK|BAD|NO)" ), string: s, icase: TRUE );
			if(!isnull( m )){
				resp = m[1];
				break;
			}
			resp = "";
			if(n > 256){
				break;
			}
		}
	}
	if(isnull( resp )){
		++tag;
		c = NASLString( "a", NASLString( tag ), " LOGIN ", user, " ", pass );
		send( socket: soc, data: NASLString( c, "\\r\\n" ) );
		n = 0;
		for(;s = recv_line( socket: soc, length: 1024 );){
			n++;
			s = chomp( s );
			m = eregmatch( pattern: NASLString( "^a", NASLString( tag ), " (OK|BAD|NO)" ), string: s, icase: TRUE );
			if(!isnull( m )){
				resp = m[1];
				break;
			}
			resp = "";
			if(n > 256){
				break;
			}
		}
	}
	imap_close_socket( socket: soc, id: tag );
	if(resp && IsMatchRegexp( resp, "OK" )){
		report = "The remote IMAP server accepts logins via the following cleartext authentication mechanisms over unencrypted connections:\nAUTHENTICATE \"PLAIN\"";
		if(STARTTLS){
			report += "\n\nThe remote IMAP server supports the \'STARTTLS\' command but isn\'t enforcing the use of it for the cleartext authentication mechanisms.";
		}
		security_message( port: port, data: report );
		exit( 0 );
	}
	exit( 99 );
}
exit( 0 );

