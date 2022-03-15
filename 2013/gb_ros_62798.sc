CPE = "cpe:/o:siemens:ruggedcom_rugged_operating_system";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103803" );
	script_bugtraq_id( 62798 );
	script_version( "2019-10-01T13:57:53+0000" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2019-10-01 13:57:53 +0000 (Tue, 01 Oct 2019)" );
	script_tag( name: "creation_date", value: "2013-10-10 17:14:09 +0200 (Thu, 10 Oct 2013)" );
	script_name( "RuggedCom Rugged Operating System Remote Security Bypass Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "This script is Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_siemens_ruggedcom_consolidation.sc" );
	script_mandatory_keys( "siemens_ruggedcom/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/62798" );
	script_tag( name: "impact", value: "An attacker may exploit this issue to bypass certain security
  restrictions and perform unauthorized actions." );
	script_tag( name: "vuldetect", value: "Check the Rugged Operating System version." );
	script_tag( name: "insight", value: "The security issue is caused due to an error when handling
  alarms configuration within the web user interface, which can be exploited
  by guest and operator users to manipulate otherwise inaccessible
  alarm configuration settings." );
	script_tag( name: "solution", value: "Updates are available. Please see the references or vendor advisory
  for more information." );
	script_tag( name: "summary", value: "Rugged Operating System is prone to a security-bypass vulnerability." );
	script_tag( name: "affected", value: "Rugged Operating System prior to 3.12.2 are vulnerable." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "3.12.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.12.2" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

