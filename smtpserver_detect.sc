if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10263" );
	script_version( "2020-11-24T13:11:48+0000" );
	script_tag( name: "last_modification", value: "2020-11-24 13:11:48 +0000 (Tue, 24 Nov 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "SMTP Server type and version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 SecuriTeam" );
	script_family( "Service detection" );
	script_dependencies( "find_service_3digits.sc", "check_smtp_helo.sc" );
	script_require_ports( "Services/smtp", 25, 465, 587 );
	script_tag( name: "summary", value: "This detects the SMTP Server's type and version by connecting to
  the server and processing the buffer received." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("smtp_func.inc.sc");
require("host_details.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
ports = smtp_get_ports();
for port in ports {
	banner = smtp_get_banner( port: port );
	if(!banner){
		continue;
	}
	guess = NULL;
	commands = NULL;
	if(service_is_unknown( port: port )){
		service_register( port: port, proto: "smtp", message: "A SMTP Server seems to be running on this port." );
	}
	set_kb_item( name: "smtp/banner/available", value: TRUE );
	set_kb_item( name: "pop3_imap_or_smtp/banner/available", value: TRUE );
	quit = get_kb_item( "smtp/fingerprints/" + port + "/quit_banner" );
	help = get_kb_item( "smtp/fingerprints/" + port + "/help_banner" );
	rset = get_kb_item( "smtp/fingerprints/" + port + "/rset_banner" );
	if( get_port_transport( port ) > ENCAPS_IP ){
		ehlo = get_kb_item( "smtp/fingerprints/" + port + "/tls_ehlo_banner" );
		is_tls = TRUE;
	}
	else {
		ehlo = get_kb_item( "smtp/fingerprints/" + port + "/nontls_ehlo_banner" );
		is_tls = FALSE;
	}
	if(ContainsString( banner, "qmail" ) || ContainsString( help, "qmail" )){
		set_kb_item( name: "smtp/qmail/detected", value: TRUE );
		set_kb_item( name: "smtp/" + port + "/qmail/detected", value: TRUE );
		guess += "\n- Qmail";
	}
	if(ContainsString( banner, "XMail " )){
		set_kb_item( name: "smtp/xmail/detected", value: TRUE );
		set_kb_item( name: "smtp/" + port + "/xmail/detected", value: TRUE );
		guess += "\n- XMail";
	}
	if(egrep( pattern: ".*nbx.*Service ready.*", string: banner )){
		set_kb_item( name: "smtp/3comnbx/detected", value: TRUE );
		set_kb_item( name: "smtp/" + port + "/3comnbx/detected", value: TRUE );
		guess += "\n- 3comnbx";
	}
	if(ContainsString( banner, "ZMailer Server" ) || ( ContainsString( help, "This mail-server is at Yoyodyne Propulsion Inc." ) && ContainsString( quit, "Out" ) && ContainsString( help, "zmhacks@nic.funet.fi" ) )){
		set_kb_item( name: "smtp/zmailer/detected", value: TRUE );
		set_kb_item( name: "smtp/" + port + "/zmailer/detected", value: TRUE );
		str = egrep( pattern: " ZMailer ", string: banner );
		if( str ){
			str = ereg_replace( pattern: "^.*ZMailer Server ([0-9a-z\\.\\-]+) .*$", string: str, replace: "\\1" );
			guess += "\n- ZMailer version " + str;
		}
		else {
			guess += "\n- ZMailer";
		}
	}
	if(ContainsString( banner, "CheckPoint FireWall-1" )){
		set_kb_item( name: "smtp/firewall-1/detected", value: TRUE );
		set_kb_item( name: "smtp/" + port + "/firewall-1/detected", value: TRUE );
		guess += "\n- CheckPoint FireWall-1";
	}
	if(ContainsString( banner, "InterMail" ) || ( ContainsString( help, "This SMTP server is a part of the InterMail E-mail system" ) && ContainsString( rset, "Ok resetting state." ) && ContainsString( quit, "ESMTP server closing connection." ) )){
		set_kb_item( name: "smtp/intermail/detected", value: TRUE );
		set_kb_item( name: "smtp/" + port + "/intermail/detected", value: TRUE );
		str = egrep( pattern: "InterMail ", string: banner );
		if( str ){
			str = ereg_replace( pattern: "^.*InterMail ([A-Za-z0-9\\.\\-]+).*$", string: str, replace: "\\1" );
			guess += "\n- InterMail version " + str;
		}
		else {
			guess += "\n- InterMail";
		}
	}
	if(ContainsString( banner, "mail rejector" ) || ( ehlo && match( pattern: "*snubby*", string: ehlo, icase: TRUE ) )){
		set_kb_item( name: "smtp/snubby/detected", value: TRUE );
		set_kb_item( name: "smtp/" + port + "/snubby/detected", value: TRUE );
		smtp_set_is_marked_wrapped( port: port );
		guess += "\n- Snubby Mail Rejector (not a real SMTP server)";
		report = "Verisign mail rejector appears to be running on this port. You probably mistyped your hostname and the scanner is scanning the wildcard address in the .COM or .NET domain.";
		report += "\n\nSolution: enter a correct hostname";
		log_message( port: port, data: report );
	}
	if(egrep( pattern: "Mail(Enable| Enable SMTP) Service", string: banner )){
		set_kb_item( name: "smtp/mailenable/detected", value: TRUE );
		set_kb_item( name: "smtp/" + port + "/mailenable/detected", value: TRUE );
		guess += "\n- MailEnable SMTP";
	}
	if(ContainsString( banner, " MDaemon " )){
		set_kb_item( name: "smtp/mdaemon/detected", value: TRUE );
		set_kb_item( name: "smtp/" + port + "/mdaemon/detected", value: TRUE );
		guess += "\n- MDaemon SMTP";
	}
	if(ContainsString( banner, " InetServer " )){
		set_kb_item( name: "smtp/inetserver/detected", value: TRUE );
		set_kb_item( name: "smtp/" + port + "/inetserver/detected", value: TRUE );
		guess += "\n- A-V Tronics InetServ SMTP";
	}
	if(ContainsString( banner, "Quick 'n Easy Mail Server" )){
		set_kb_item( name: "smtp/quickneasy/detected", value: TRUE );
		set_kb_item( name: "smtp/" + port + "/quickneasy/detected", value: TRUE );
		guess += "\n" + "- Quick 'n Easy Mail Server";
	}
	if(ContainsString( banner, "QK SMTP Server" )){
		set_kb_item( name: "smtp/qk_smtp/detected", value: TRUE );
		set_kb_item( name: "smtp/" + port + "/qk_smtp/detected", value: TRUE );
		guess += "\n- QK SMTP Server";
	}
	if(ContainsString( banner, "ESMTP CommuniGate Pro" )){
		set_kb_item( name: "smtp/communigate/pro/detected", value: TRUE );
		set_kb_item( name: "smtp/" + port + "/communigate/pro/detected", value: TRUE );
		guess += "\n- CommuniGate Pro";
	}
	if(ContainsString( banner, "TABS Mail Server" )){
		set_kb_item( name: "smtp/tabs/mailcarrier/detected", value: TRUE );
		set_kb_item( name: "smtp/" + port + "/tabs/mailcarrier/detected", value: TRUE );
		guess += "\n- TABS MailCarrier";
	}
	if(ContainsString( banner, "ESMTPSA" )){
		set_kb_item( name: "smtp/esmtpsa/detected", value: TRUE );
		set_kb_item( name: "smtp/" + port + "/esmtpsa/detected", value: TRUE );
		guess += "\n- Various Mail Server like Rumble SMTP";
	}
	if(IsMatchRegexp( banner, "^220.*SonicWall " )){
		set_kb_item( name: "smtp/sonicwall/email_security/detected", value: TRUE );
		set_kb_item( name: "smtp/" + port + "/sonicwall/email_security/detected", value: TRUE );
		guess += "\n- SonicWall Email Security SMTP";
	}
	if(IsMatchRegexp( banner, "^220 [^ ]+ ESMTP$" ) || ContainsString( banner, "Powered by the new deepOfix Mail Server" ) || ContainsString( banner, "Welcome to deepOfix" ) || ContainsString( help, "qmail" )){
		set_kb_item( name: "smtp/deepofix/detected", value: TRUE );
		set_kb_item( name: "smtp/" + port + "/deepofix/detected", value: TRUE );
		guess += "\n- deepOfix";
	}
	if(IsMatchRegexp( banner, "FirstClass [A-Z]?SMTP" )){
		set_kb_item( name: "smtp/opentext/firstclass/detected", value: TRUE );
		set_kb_item( name: "smtp/" + port + "/opentext/firstclass/detected", value: TRUE );
		guess += "\n- OpenText FirstClass";
	}
	if(IsMatchRegexp( banner, "ESMTP Xpressions" )){
		set_kb_item( name: "smtp/unify/xpressions/detected", value: TRUE );
		set_kb_item( name: "smtp/" + port + "/unify/xpressions/detected", value: TRUE );
		guess += "\n- Unify OpenScape Xpressions";
	}
	if(IsMatchRegexp( banner, "ArgoSoft Mail Server" )){
		set_kb_item( name: "smtp/argosoft/mailserver/detected", value: TRUE );
		set_kb_item( name: "smtp/" + port + "/argosoft/mailserver/detected", value: TRUE );
		guess += "\n- ArgoSoft Mail Server";
	}
	if(IsMatchRegexp( banner, "(HCL|IBM|Lotus) Domino" )){
		set_kb_item( name: "smtp/hcl/domino/detected", value: TRUE );
		set_kb_item( name: "smtp/" + port + "/hcl/domino/detected", value: TRUE );
		guess += "\n- HCL | IBM | Lotus Domino";
	}
	if(IsMatchRegexp( banner, "IceWarp" )){
		set_kb_item( name: "smtp/icewarp/mailserver/detected", value: TRUE );
		set_kb_item( name: "smtp/" + port + "/icewarp/mailserver/detected", value: TRUE );
		guess += "\n- IceWarp Mail Server";
	}
	if(banner == "220 ESMTP IMSVA"){
		set_kb_item( name: "smtp/trend_micro/imsva/detected", value: TRUE );
		set_kb_item( name: "smtp/" + port + "/trend_micro/imsva/detected", value: TRUE );
		guess += "\n- Trend Micro Interscan Messaging Security Virtual Appliance (IMSVA)";
	}
	report = "Remote SMTP server banner:\n\n" + banner;
	if(strlen( guess ) > 0){
		report += "\n\nThis is probably:\n" + guess;
	}
	if( is_tls ) {
		commandlist = get_kb_list( "smtp/fingerprints/" + port + "/tls_commandlist" );
	}
	else {
		commandlist = get_kb_list( "smtp/fingerprints/" + port + "/nontls_commandlist" );
	}
	if(commandlist && is_array( commandlist )){
		commandlist = sort( commandlist );
		for command in commandlist {
			if( !commands ) {
				commands = command;
			}
			else {
				commands += ", " + command;
			}
		}
	}
	if(strlen( commands ) > 0){
		ehlo_report = "\n\nThe remote SMTP server is announcing the following available ESMTP commands (EHLO response) via an ";
		if( is_tls ) {
			ehlo_report += "encrypted";
		}
		else {
			ehlo_report += "unencrypted";
		}
		report += ehlo_report += " connection:\n\n" + commands;
	}
	log_message( port: port, data: report );
}
exit( 0 );

