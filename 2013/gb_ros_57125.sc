CPE = "cpe:/o:siemens:ruggedcom_rugged_operating_system";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103634" );
	script_bugtraq_id( 57125 );
	script_version( "2019-10-01T13:57:53+0000" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:P/A:P" );
	script_tag( name: "last_modification", value: "2019-10-01 13:57:53 +0000 (Tue, 01 Oct 2019)" );
	script_tag( name: "creation_date", value: "2013-01-04 12:49:46 +0100 (Fri, 04 Jan 2013)" );
	script_name( "Rugged Operating System Web UI Multiple Security Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "This script is Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_siemens_ruggedcom_consolidation.sc" );
	script_mandatory_keys( "siemens_ruggedcom/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/57125" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "Rugged Operating System is prone to multiple security vulnerabilities
  including:

  1. A session-hijacking vulnerability

  2. An unauthorized-access vulnerability" );
	script_tag( name: "impact", value: "Successfully exploiting these issues may allow an attacker to gain
  unauthorized access to the affected application, bypass certain security restrictions and perform
  unauthorized actions." );
	script_tag( name: "affected", value: "Rugged Operating System versions prior to 3.12.1 are vulnerable." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "3.12.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.12.1" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

