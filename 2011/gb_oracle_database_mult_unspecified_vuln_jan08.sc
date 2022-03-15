CPE = "cpe:/a:oracle:database_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802528" );
	script_version( "$Revision: 12047 $" );
	script_cve_id( "CVE-2008-0339", "CVE-2008-0340", "CVE-2008-0341", "CVE-2008-0342", "CVE-2008-0343", "CVE-2008-0344", "CVE-2008-0345" );
	script_bugtraq_id( 27229 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-24 09:38:41 +0200 (Wed, 24 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-12-07 12:35:57 +0530 (Wed, 07 Dec 2011)" );
	script_name( "Oracle Database Server Multiple Unspecified Vulnerabilities - Jan 08" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "oracle_tnslsnr_version.sc" );
	script_mandatory_keys( "OracleDatabaseServer/installed" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/28518" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1019218" );
	script_xref( name: "URL", value: "http://www.us-cert.gov/cas/techalerts/TA08-017A.html" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpujan2008-086860.html" );
	script_tag( name: "impact", value: "An unspecified impact and attack vectors." );
	script_tag( name: "affected", value: "Oracle Database server versions 8.1.7.4, 9.0.1.5, 9.2.0.6, 10.1.0.3, 9.2.0.7,
  10.1.0.5, 10.2.0.1, 9.0.1.5 FIPS, 9.0.1.5 FIPS+, 9.2.0.8, 9.2.0.8DV,
  10.1.0.5, 10.2.0.3, 10.1.0.4 and 11.1.0.6" );
	script_tag( name: "insight", value: "The flaws are due to unspecified errors in the multiple components." );
	script_tag( name: "summary", value: "This host is running Oracle database and is prone to multiple
  unspecified vulnerabilities." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
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
if(version_in_range( version: vers, test_version: "10.2.0.0", test_version2: "10.2.0.2" ) || version_in_range( version: vers, test_version: "9.0.1", test_version2: "9.0.1.4" ) || version_in_range( version: vers, test_version: "8.1.0", test_version2: "8.1.7.3" ) || version_in_range( version: vers, test_version: "9.2.0", test_version2: "9.2.0.7" ) || version_in_range( version: vers, test_version: "10.1.0", test_version2: "10.1.0.4" ) || version_in_range( version: vers, test_version: "11.1.0", test_version2: "11.1.0.5" ) || version_is_equal( version: vers, test_version: "8.1.7.4" ) || version_is_equal( version: vers, test_version: "9.0.1.5" ) || version_is_equal( version: vers, test_version: "9.2.0.8" ) || version_is_equal( version: vers, test_version: "10.1.0.5" ) || version_is_equal( version: vers, test_version: "10.2.0.3" ) || version_is_equal( version: vers, test_version: "11.1.0.6" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See references" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

