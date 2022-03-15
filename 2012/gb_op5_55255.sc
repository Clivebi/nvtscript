CPE = "cpe:/a:op5:monitor";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103557" );
	script_bugtraq_id( 55255 );
	script_version( "2021-04-22T08:55:01+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:P/A:N" );
	script_name( "op5 Monitor Unspecified SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/55255" );
	script_tag( name: "last_modification", value: "2021-04-22 08:55:01 +0000 (Thu, 22 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-08-30 11:27:11 +0200 (Thu, 30 Aug 2012)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gb_op5_detect.sc" );
	script_mandatory_keys( "OP5/installed" );
	script_tag( name: "solution", value: "Reportedly, the issue is fixed in the beta version. Please contact the
  vendor for more information." );
	script_tag( name: "summary", value: "op5 Monitor is prone to an unspecified SQL-injection vulnerability
  because it fails to sufficiently sanitize user-supplied data before using it in an SQL query." );
	script_tag( name: "impact", value: "Exploiting this issue could allow an attacker to compromise the
  application, access or modify data, or exploit latent vulnerabilities in the underlying database." );
	script_tag( name: "affected", value: "op5 Monitor versions 2.7.3 and prior are affected." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(vers = get_app_version( cpe: CPE, port: port )){
	if(version_is_less_equal( version: vers, test_version: "2.7.3" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "Less than or equal to 2.7.3" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

