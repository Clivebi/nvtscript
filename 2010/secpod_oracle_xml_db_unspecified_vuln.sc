CPE = "cpe:/a:oracle:database_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902043" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-04-23 17:57:39 +0200 (Fri, 23 Apr 2010)" );
	script_cve_id( "CVE-2010-0851" );
	script_bugtraq_id( 39434 );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_name( "Oracle Database 'XML DB component' Unspecified vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "oracle_tnslsnr_version.sc" );
	script_mandatory_keys( "OracleDatabaseServer/installed" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/39438" );
	script_xref( name: "URL", value: "http://en.securitylab.ru/nvd/392881.php" );
	script_xref( name: "URL", value: "http://www.us-cert.gov/cas/techalerts/TA10-103B.html" );
	script_xref( name: "URL", value: "http://www.juniper.net/security/auto/vulnerabilities/vuln39434.html" );
	script_xref( name: "URL", value: "http://www.oracle.com/technology/deploy/security/critical-patch-updates/cpuapr2010.html" );
	script_tag( name: "impact", value: "Successful exploitation will let remote authenticated users to affect
  confidentiality via unknown vectors." );
	script_tag( name: "affected", value: "Oracle Database versions 9.2.0.8, 9.2.0.8DV, 10.1.0.5 and 10.2.0.3." );
	script_tag( name: "insight", value: "The flaw is due to unspecified errors in the 'XML DB component',
  and unknown impact and attack vectors." );
	script_tag( name: "summary", value: "This host is running Oracle database and is prone to unspecified
  vulnerability." );
	script_tag( name: "solution", value: "Apply the update from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "9.2.0.8DV" ) || version_is_equal( version: vers, test_version: "10.1.0.5" ) || version_is_equal( version: vers, test_version: "10.2.0.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See references" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

