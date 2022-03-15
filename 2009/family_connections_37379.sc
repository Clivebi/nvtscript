CPE = "cpe:/a:haudenschilt:family_connections_cms";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100408" );
	script_version( "$Revision: 14031 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2009-12-17 19:46:08 +0100 (Thu, 17 Dec 2009)" );
	script_bugtraq_id( 37379 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Family Connections Multiple Input Validation Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/37379" );
	script_xref( name: "URL", value: "http://www.haudenschilt.com/fcms/index.html" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "family_connections_detect.sc" );
	script_mandatory_keys( "family_connections/installed" );
	script_tag( name: "summary", value: "Family Connections is prone to multiple input-validation vulnerabilities,
  including a local file-include issue, an arbitrary file-upload issue, and multiple SQL-injection issues. These
  issues occur because the application fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "Exploiting these issues may allow an unauthorized user to view files and execute
  local scripts, execute arbitrary script code, access or modify data, or exploit latent vulnerabilities in the
  underlying database implementation." );
	script_tag( name: "affected", value: "Family Connections versions 2.1.3 and prior are affected." );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "2.1.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.2" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

