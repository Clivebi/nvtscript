CPE = "cpe:/a:microsoft:exchange_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11053" );
	script_version( "2020-03-23T13:51:29+0000" );
	script_tag( name: "last_modification", value: "2020-03-23 13:51:29 +0000 (Mon, 23 Mar 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 5306 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2002-0698" );
	script_name( "IMC SMTP EHLO Buffer Overrun" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2002 SECNAP Network Security, LLC" );
	script_family( "SMTP problems" );
	script_dependencies( "sw_ms_exchange_server_remote_detect.sc" );
	script_mandatory_keys( "microsoft/exchange_server/smtp/detected" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2002/ms02-037" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see thee references
  for more information." );
	script_tag( name: "summary", value: "A security vulnerability results because of an unchecked buffer
  in the IMC code that generates the response to the EHLO protocol command." );
	script_tag( name: "impact", value: "If the buffer were overrun with data it would result in either the
  failure of the IMC or could allow the attacker to run code in the security context of the IMC,
  which runs as Exchange5.5 Service Account." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smtp_func.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "smtp" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
banner = smtp_get_banner( port: port );
if(!banner || !egrep( pattern: "^220.*Microsoft Exchange Internet.*", string: banner )){
	exit( 0 );
}
if(egrep( string: banner, pattern: "Service.5\\.[6-9]" )){
	exit( 99 );
}
if(egrep( string: banner, pattern: "Service.5\\.5\\.[3-9]" )){
	exit( 99 );
}
if(egrep( string: banner, pattern: "Service.5\\.5\\.2[7-9]" )){
	exit( 99 );
}
if(egrep( string: banner, pattern: "Service.5\\.5\\.26[6-9]" )){
	exit( 99 );
}
if(egrep( string: banner, pattern: "Service.5\\.5\\.265[6-9]" )){
	exit( 99 );
}
security_message( port: port );

