CPE = "cpe:/a:oracle:database_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802522" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2007-3855" );
	script_bugtraq_id( 24887 );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2011-12-07 12:23:56 +0530 (Wed, 07 Dec 2011)" );
	script_name( "Oracle Database Server Multiple Components Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "oracle_tnslsnr_version.sc" );
	script_mandatory_keys( "OracleDatabaseServer/installed" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/26114" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/35495" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id?1018415" );
	script_xref( name: "URL", value: "http://www.us-cert.gov/cas/techalerts/TA07-200A.html" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/474326/100/0/threaded" );
	script_xref( name: "URL", value: "http://www.red-database-security.com/advisory/oracle_view_vulnerability.html" );
	script_tag( name: "impact", value: "Successful exploitation allows remote authenticated users to execute
  arbitrary SQL commands via unknown vectors." );
	script_tag( name: "affected", value: "Oracle Database server versions 9.0.1.5, 9.2.0.8, 9.2.0.8DV, 10.1.0.5
  and 10.2.0.3" );
	script_tag( name: "insight", value: "Flaw is due to:

  - An unspecified errors in DataGuard, PL/SQL and Spatial components.

  - An error in SQL compiler, allows a remote attacker with 'Create Session'
    privileges on the SQL Compiler component to perform unauthorized inserts,
    updates, and deletes in the database using specially-crafted views." );
	script_tag( name: "summary", value: "This host is running Oracle database and is prone to multiple
  vulnerabilities." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpujul2007-087014.html" );
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
if(version_in_range( version: vers, test_version: "10.1.0", test_version2: "10.1.0.4" ) || version_in_range( version: vers, test_version: "10.2.0", test_version2: "10.2.0.2" ) || version_in_range( version: vers, test_version: "9.0.1", test_version2: "9.0.1.4" ) || version_in_range( version: vers, test_version: "9.2.0", test_version2: "9.2.0.7" ) || version_is_equal( version: vers, test_version: "9.0.1.5" ) || version_is_equal( version: vers, test_version: "9.2.0.8" ) || version_is_equal( version: vers, test_version: "10.1.0.5" ) || version_is_equal( version: vers, test_version: "10.2.0.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See references" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

