if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14712" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_bugtraq_id( 11144 );
	script_name( "MailEnable SMTP Connector Service DNS Lookup DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 George A. Theall" );
	script_family( "Denial of Service" );
	script_dependencies( "smtpserver_detect.sc" );
	script_mandatory_keys( "smtp/mailenable/detected" );
	script_tag( name: "impact", value: "A remote attacker can exploit this to perform a DoS attack against the
  SMTP server on the target." );
	script_tag( name: "solution", value: "Upgrade to MailEnable Standard Edition 1.8 / Professional
  Edition 1.5e or later." );
	script_tag( name: "summary", value: "The target is running at least one instance of MailEnable's SMTP
  Connector service. A flaw exists in both the Standard Edition 1.7x and Professional Edition
  1.2x/1.5a-e that results in this service crashing if it receives a DNS response with over 100 MX records." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("smtp_func.inc.sc");
require("version_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = smtp_get_port( default: 25 );
banner = smtp_get_banner( port: port );
if(!banner || !IsMatchRegexp( banner, "Mail(Enable| Enable SMTP) Service" )){
	exit( 0 );
}
ver = eregmatch( pattern: "Version: (0-)?([0-9][^-]+)-", string: banner, icase: TRUE );
if(isnull( ver )){
	exit( 0 );
}
if( isnull( ver[1] ) ){
	edition = "Standard Edition";
}
else {
	if(ver[1] == "0-"){
		edition = "Professional Edition";
	}
}
if(isnull( edition )){
	exit( 0 );
}
ver = ver[2];
if( edition == "Standard Edition" ){
	if(IsMatchRegexp( ver, "^1\\.7" )){
		report = report_fixed_ver( installed_ver: edition + " " + ver, fixed_version: edition + " 1.8" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
else {
	if(edition == "Professional"){
		if(IsMatchRegexp( ver, "^1\\.(2|5[a-e])" )){
			report = report_fixed_ver( installed_ver: edition + " " + ver, fixed_version: edition + " 1.5e" );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

