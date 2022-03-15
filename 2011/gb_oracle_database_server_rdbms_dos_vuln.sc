CPE = "cpe:/a:oracle:database_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802539" );
	script_version( "$Revision: 12047 $" );
	script_cve_id( "CVE-2007-5506" );
	script_bugtraq_id( 26108 );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-24 09:38:41 +0200 (Wed, 24 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-12-08 15:30:42 +0530 (Thu, 08 Dec 2011)" );
	script_name( "Oracle Database Server 'RDBMS' component Denial of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "oracle_tnslsnr_version.sc" );
	script_mandatory_keys( "OracleDatabaseServer/installed" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/27409" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id?1018823" );
	script_xref( name: "URL", value: "http://securityreason.com/securityalert/3244" );
	script_xref( name: "URL", value: "http://www.us-cert.gov/cas/techalerts/TA07-290A.html" );
	script_tag( name: "impact", value: "Successful exploitation allows an attacker to cause denial of service by
  sending packets of type 6 - Data packets." );
	script_tag( name: "affected", value: "Oracle Database 9.0.1.5, 9.2.0.8, 9.2.0.8, 10.1.0.5 and 10.2.0.3" );
	script_tag( name: "insight", value: "The flaw is due to error in 'RDBMS' component, which allows attackers
  to cause a denial of service (CPU consumption) via a crafted type 6 Data
  packet, aka DB20." );
	script_tag( name: "summary", value: "This host is running Oracle database and is prone to denial of
  service vulnerability" );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpuoct2007-092913.html" );
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
if(version_in_range( version: vers, test_version: "9.0.1", test_version2: "9.0.1.4" ) || version_in_range( version: vers, test_version: "9.2.0", test_version2: "9.2.0.7" ) || version_in_range( version: vers, test_version: "10.1.0", test_version2: "10.1.0.4" ) || version_in_range( version: vers, test_version: "10.2.0", test_version2: "10.2.0.2" ) || version_is_equal( version: vers, test_version: "9.0.1.5" ) || version_is_equal( version: vers, test_version: "9.2.0.8" ) || version_is_equal( version: vers, test_version: "10.2.0.3" ) || version_is_equal( version: vers, test_version: "10.1.0.5" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See references" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

