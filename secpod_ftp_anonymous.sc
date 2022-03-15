if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108477" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-03-12 10:50:11 +0100 (Thu, 12 Mar 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Anonymous FTP Login Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Service detection" );
	script_dependencies( "find_service2.sc", "find_service_3digits.sc", "logins.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_tag( name: "summary", value: "Checks if the remote FTP Server allows anonymous logins.

  Note: The reporting takes place in a separate VT 'Anonymous FTP Login Reporting' (OID: 1.3.6.1.4.1.25623.1.0.900600)." );
	script_tag( name: "vuldetect", value: "Try to login with an anonymous account at the remote FTP Server." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
report = "It was possible to login to the remote FTP service with the following anonymous account(s):\n\n";
listingReport = "\nHere are the contents of the remote FTP directory listing:\n";
passwd = "anonymous@example.com";
port = ftp_get_port( default: 21 );
for user in make_list( "anonymous",
	 "ftp" ) {
	soc1 = open_sock_tcp( port );
	if(!soc1){
		continue;
	}
	login_details = ftp_log_in( socket: soc1, user: user, pass: passwd );
	if(!login_details){
		ftp_close( socket: soc1 );
		continue;
	}
	vuln = TRUE;
	report += user + ":" + passwd + "\n";
	set_kb_item( name: "ftp/" + port + "/anonymous", value: TRUE );
	set_kb_item( name: "ftp/anonymous_ftp/detected", value: TRUE );
	if(!get_kb_item( "ftp/login" )){
		set_kb_item( name: "ftp/login", value: user );
		set_kb_item( name: "ftp/password", value: passwd );
	}
	if(!get_kb_item( "ftp/anonymous/login" )){
		set_kb_item( name: "ftp/anonymous/login", value: user );
		set_kb_item( name: "ftp/anonymous/password", value: passwd );
	}
	port2 = ftp_get_pasv_port( socket: soc1 );
	if(!port2){
		ftp_close( socket: soc1 );
		continue;
	}
	soc2 = open_sock_tcp( port: port2, transport: get_port_transport( port ) );
	if(!soc2){
		ftp_close( socket: soc1 );
		continue;
	}
	send( socket: soc1, data: "LIST /\r\n" );
	listing = ftp_recv_listing( socket: soc2 );
	close( soc2 );
	ftp_close( socket: soc1 );
	if(listing && strlen( listing )){
		listingAvailable = TRUE;
		listingReport += "\nAccount \"" + user + "\":\n\n" + listing;
	}
}
if(vuln){
	if(listingAvailable){
		report += listingReport;
	}
	set_kb_item( name: "ftp/" + port + "/anonymous_report", value: report );
}
exit( 0 );

