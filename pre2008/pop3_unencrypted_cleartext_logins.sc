if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15855" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "4.8" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:P/I:P/A:N" );
	script_xref( name: "OSVDB", value: "3119" );
	script_name( "POP3 Unencrypted Cleartext Login" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 George A. Theall" );
	script_family( "General" );
	script_dependencies( "popserver_detect.sc", "gb_starttls_pop3.sc", "logins.sc" );
	script_require_ports( "Services/pop3", 110, 995 );
	script_mandatory_keys( "pop3/banner/available" );
	script_xref( name: "URL", value: "http://www.ietf.org/rfc/rfc2222.txt" );
	script_xref( name: "URL", value: "http://www.ietf.org/rfc/rfc2595.txt" );
	script_tag( name: "impact", value: "An attacker can uncover user names and passwords by sniffing traffic to the POP3
  daemon if a less secure authentication mechanism (eg, USER command, AUTH PLAIN, AUTH LOGIN) is used." );
	script_tag( name: "solution", value: "Configure the remote server to always enforce encrypted connections via
  SSL/TLS with the 'STLS' command." );
	script_tag( name: "summary", value: "The remote host is running a POP3 daemon that allows cleartext logins over
  unencrypted connections.

  NOTE: Depending on the POP3 server configuration valid credentials needs to be given to the settings of
  'Login configurations' OID: 1.3.6.1.4.1.25623.1.0.10870." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("pop3_func.inc.sc");
port = pop3_get_port( default: 110 );
encaps = get_port_transport( port );
if(encaps > ENCAPS_IP){
	exit( 0 );
}
banner = pop3_get_banner( port: port );
if(!banner){
	exit( 0 );
}
if(get_kb_item( "pop3/" + port + "/starttls" )){
	STARTTLS = TRUE;
}
done = FALSE;
report = "";
capalist = get_kb_list( "pop3/fingerprints/" + port + "/nontls_capalist" );
if(capalist && is_array( capalist )){
	for capa in capalist {
		if(capa == "."){
			continue;
		}
		if(egrep( string: capa, pattern: "^(SASL (PLAIN|LOGIN)|USER)", icase: TRUE )){
			VULN = TRUE;
			report += "\n" + capa;
		}
	}
	done = TRUE;
}
if(VULN){
	report = "The remote POP3 server accepts logins via the following cleartext authentication mechanisms over unencrypted connections:\n" + report;
	if(STARTTLS){
		report += "\n\nThe remote POP3 server supports the \'STLS\' command but isn\'t enforcing the use of it for the cleartext authentication mechanisms.";
	}
	security_message( port: port, data: report );
	exit( 0 );
}
if(done){
	exit( 99 );
}
if(!done){
	kb_creds = pop3_get_kb_creds();
	user = kb_creds["login"];
	pass = kb_creds["pass"];
	if(!user || !pass){
		exit( 0 );
	}
	soc = open_sock_tcp( port );
	if(!soc){
		exit( 0 );
	}
	s = recv_line( socket: soc, length: 1024 );
	if(!pop3_verify_banner( data: s )){
		close( soc );
		exit( 0 );
	}
	send( socket: soc, data: NASLString( "AUTH PLAIN\\r\\n" ) );
	s = recv_line( socket: soc, length: 1024 );
	s = chomp( s );
	if(IsMatchRegexp( s, "^\\+" )){
		c = base64( str: raw_string( 0, user, 0, pass ) );
		send( socket: soc, data: NASLString( c, "\\r\\n" ) );
		n = 0;
		for(;s = recv_line( socket: soc, length: 1024 );){
			n++;
			m = eregmatch( pattern: "^(\\+OK|-ERR) ", string: chomp( s ), icase: TRUE );
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
		send( socket: soc, data: NASLString( "USER ", user, "\\r\\n" ) );
		n = 0;
		for(;s = recv_line( socket: soc, length: 1024 );){
			n++;
			m = eregmatch( pattern: "^(\\+OK|-ERR) ", string: chomp( s ), icase: TRUE );
			if(!isnull( m )){
				resp = m[1];
				break;
			}
			resp = "";
			if(n > 256){
				break;
			}
		}
		if(resp && IsMatchRegexp( resp, "OK" )){
			n = 0;
			send( socket: soc, data: NASLString( "PASS ", pass, "\\r\\n" ) );
			for(;s = recv_line( socket: soc, length: 1024 );){
				n++;
				m = eregmatch( pattern: "^(\\+OK|-ERR) ", string: chomp( s ), icase: TRUE );
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
	}
	pop3_close_socket( socket: soc );
	if(resp && IsMatchRegexp( resp, "OK" )){
		report = "The remote POP3 server accepts logins via the following cleartext authentication mechanisms over unencrypted connections:\nAUTH PLAIN";
		if(STARTTLS){
			report += "\n\nThe remote POP3 server supports the \'STLS\' command but isn\'t enforcing the use of it for the cleartext authentication mechanisms.";
		}
		security_message( port: port, data: report );
		exit( 0 );
	}
	exit( 99 );
}
exit( 0 );

