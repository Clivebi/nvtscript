CPE = "cpe:/a:oracle:database_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802523" );
	script_version( "2019-05-20T06:24:13+0000" );
	script_cve_id( "CVE-2007-0272" );
	script_bugtraq_id( 22083 );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-05-20 06:24:13 +0000 (Mon, 20 May 2019)" );
	script_tag( name: "creation_date", value: "2011-12-07 12:25:28 +0530 (Wed, 07 Dec 2011)" );
	script_name( "Oracle Database Server MDSYS.MD Buffer Overflows and Denial of Service Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "oracle_tnslsnr_version.sc" );
	script_mandatory_keys( "OracleDatabaseServer/installed" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1017522" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/31541" );
	script_xref( name: "URL", value: "http://www.us-cert.gov/cas/techalerts/TA07-017A.html" );
	script_xref( name: "URL", value: "http://www.appsecinc.com/resources/alerts/oracle/2007-05.shtml" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/474047/100/0/threaded" );
	script_tag( name: "impact", value: "Successful exploitation allows an attacker to execute arbitrary code. It
  can also be exploited to cause a Denial of Service by crashing the Oracle server process." );
	script_tag( name: "affected", value: "Oracle Database server versions 8.1.7.4, 9.0.1.5, 9.2.0.7, and 10.1.0.4." );
	script_tag( name: "insight", value: "The flaws are due to an error in 'MDSYS.MD' package that is used in the
  Oracle spatial component. The package has EXECUTE permissions set to PUBLIC, so
  any Oracle database user can exploit the vulnerability to execute arbitrary code." );
	script_tag( name: "summary", value: "This host is running Oracle database and is prone to a Buffer
  Overflow and Denial of Service vulnerabilities." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpujan2007-101493.html" );
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
if(version_in_range( version: vers, test_version: "8.1.0", test_version2: "8.1.7.3" ) || version_in_range( version: vers, test_version: "10.1.0", test_version2: "10.1.0.3" ) || version_in_range( version: vers, test_version: "9.0.1", test_version2: "9.0.1.4" ) || version_in_range( version: vers, test_version: "9.2.0", test_version2: "9.2.0.6" ) || version_is_equal( version: vers, test_version: "8.1.7.4" ) || version_is_equal( version: vers, test_version: "9.0.1.5" ) || version_is_equal( version: vers, test_version: "10.1.0.4" ) || version_is_equal( version: vers, test_version: "9.2.0.7" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See references" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

