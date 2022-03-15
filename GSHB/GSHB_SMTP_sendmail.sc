if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96098" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-06-21 10:39:50 +0200 (Mon, 21 Jun 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Check Sendmail Configuration" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_dependencies( "compliance_tests.sc", "gb_sendmail_detect.sc" );
	script_mandatory_keys( "Compliance/Launch/GSHB" );
	script_tag( name: "summary", value: "Checks the Sendmail Configuration.

  The Script test the SMTP Sendmail Server if the commands
  DEBUG, VRFY and EXPN are available." );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("smtp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
sendmail = get_kb_item( "sendmail/detected" );
if( !sendmail ){
	sendmaildebug = "nosendmail";
	sendmailvrfy = "nosendmail";
	sendmailexpn = "nosendmail";
}
else {
	port = smtp_get_port( default: 25, ignore_broken: TRUE, ignore_unscanned: TRUE );
	if( !get_port_state( port ) ){
		sendmaildebug = "noport";
		sendmailvrfy = "noport";
		sendmailexpn = "noport";
	}
	else {
		if( smtp_get_is_marked_wrapped( port: port ) ){
			sendmaildebug = "nosmtp";
			sendmailvrfy = "nosmtp";
			sendmailexpn = "nosmtp";
		}
		else {
			soc = open_sock_tcp( port );
			if( soc ){
				b = smtp_recv_banner( socket: soc );
				s = NASLString( "DEBUG\\r\\n" );
				send( socket: soc, data: s );
				r = recv_line( socket: soc, length: 1024 );
				r = tolower( r );
				if( ContainsString( r, "200 debug set" ) ) {
					sendmaildebug = "yes";
				}
				else {
					sendmaildebug = "no";
				}
				smtp_close( socket: soc, check_data: r );
			}
			else {
				sendmaildebug = "nosoc";
			}
			soc = open_sock_tcp( port );
			if( soc ){
				b = smtp_recv_banner( socket: soc );
				send( socket: soc, data: NASLString( "EHLO ", smtp_get_helo_from_kb( port: port ), "\\r\\n" ) );
				ehlotxt = smtp_recv_line( socket: soc, code: "(250|550)" );
				if(ehlotxt){
					send( socket: soc, data: NASLString( "VRFY root\\r\\n" ) );
					vrfy_txt = smtp_recv_line( socket: soc, code: "(25[0-2]|550)" );
					if( vrfy_txt && !egrep( pattern: "Administrative prohibition", string: vrfy_txt ) && !egrep( pattern: "Access Denied", string: vrfy_txt ) && !egrep( pattern: "not available", string: vrfy_txt ) && !egrep( pattern: "String does not match anything", string: vrfy_txt ) && !egrep( pattern: "Cannot VRFY user", string: vrfy_txt ) && !egrep( pattern: "VRFY disabled", string: vrfy_txt ) && !egrep( pattern: "252 send some mail, i'll try my best", string: vrfy_txt ) ){
						vtstrings = get_vt_strings();
						send( socket: soc, data: NASLString( "VRFY ", vtstrings["lowercase_rand"], "\r\n" ) );
						vrfy_txt2 = smtp_recv_line( socket: soc );
						if( vrfy_txt2 && !egrep( string: vrfy_txt2, pattern: "^252" ) ){
							sendmailvrfy = "yes";
						}
						else {
							sendmailvrfy = "no";
						}
					}
					else {
						sendmailvrfy = "no";
					}
					send( socket: soc, data: NASLString( "EXPN root\\r\\n" ) );
					expn_txt = smtp_recv_line( socket: soc, code: "(250|550)" );
					if( expn_txt && !egrep( pattern: "Administrative prohibition", string: expn_txt ) && !egrep( pattern: "Access Denied", string: expn_txt ) && !egrep( pattern: "lists are confidential", string: expn_txt ) && !egrep( pattern: "EXPN command has been disabled", string: expn_txt ) && !egrep( pattern: "not available", string: expn_txt ) ){
						sendmailexpn = "yes";
					}
					else {
						sendmailexpn = "no";
					}
				}
				smtp_close( socket: soc, check_data: ehlotxt );
			}
			else {
				sendmailvrfy = "nosoc";
				sendmailexpn = "nosoc";
			}
		}
	}
}
if(!sendmaildebug){
	sendmaildebug = "error";
}
if(!sendmailvrfy){
	sendmailvrfy = "error";
}
if(!sendmailexpn){
	sendmailexpn = "error";
}
set_kb_item( name: "GSHB/SENDMAIL/DEBUG", value: sendmaildebug );
set_kb_item( name: "GSHB/SENDMAIL/VRFX", value: sendmailvrfy );
set_kb_item( name: "GSHB/SENDMAIL/EXPN", value: sendmailexpn );
exit( 0 );

