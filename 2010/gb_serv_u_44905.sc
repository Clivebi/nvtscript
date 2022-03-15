CPE = "cpe:/a:serv-u:serv-u";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100914" );
	script_version( "2019-06-24T07:41:01+0000" );
	script_tag( name: "last_modification", value: "2019-06-24 07:41:01 +0000 (Mon, 24 Jun 2019)" );
	script_tag( name: "creation_date", value: "2010-11-25 12:46:25 +0100 (Thu, 25 Nov 2010)" );
	script_bugtraq_id( 44905 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Serv-U Empty Password Authentication Bypass Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/44905" );
	script_xref( name: "URL", value: "http://www.serv-u.com/releasenotes/" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "This script is Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_solarwinds_serv-u_consolidation.sc" );
	script_mandatory_keys( "solarwinds/servu/detected" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "Serv-U is prone to an authentication-bypass vulnerability." );
	script_tag( name: "impact", value: "Attackers can exploit this issue to gain unauthorized access to the
  affected application. However, this requires that the application has password-based authentication disabled." );
	script_tag( name: "affected", value: "Serv-U 10.2.0.2 and versions prior to 10.3.0.1 are vulnerable." );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "10.2.0.2", test_version2: "10.3.0.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "10.3.0.1" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

