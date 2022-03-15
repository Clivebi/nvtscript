if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11270" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "SMTP too long line" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2003 Michel Arboi" );
	script_family( "SMTP problems" );
	script_dependencies( "smtpserver_detect.sc", "smtp_settings.sc", "smtp_relay.sc" );
	script_require_ports( "Services/smtp", 25, 465, 587 );
	script_mandatory_keys( "smtp/banner/available" );
	script_tag( name: "summary", value: "Some antivirus scanners dies when they process an email with a
  too long string without line breaks.

  Such a message was sent. If there is an antivirus on your MTA, it might have crashed. Please check
  its status right now, as it is not possible to do it remotely." );
	script_tag( name: "solution", value: "Contact the vendor of the antivirus scanner to get an update." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_probe" );
	exit( 0 );
}
require("smtp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
fromaddr = smtp_from_header();
toaddr = smtp_to_header();
vtstrings = get_vt_strings();
port = smtp_get_port( default: 25 );
if(get_kb_item( "smtp/" + port + "/spam" )){
	exit( 0 );
}
if(smtp_get_is_marked_wrapped( port: port )){
	exit( 0 );
}
b = NASLString( "From: ", fromaddr, "\\r\\n", "To: ", toaddr, "\\r\\n", "Subject: ", vtstrings["lowercase"], " test - ignore it\\r\\n\\r\\n", crap( 10000 ), "\\r\\n" );
n = smtp_send_port( port: port, from: fromaddr, to: toaddr, body: b );
if(n > 0){
	security_message( port: port );
}

