CPE = "cpe:/a:oracle:jdk";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814407" );
	script_version( "2021-08-20T14:11:31+0000" );
	script_cve_id( "CVE-2018-3150", "CVE-2018-3157" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-20 14:11:31 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-10-17 13:00:29 +0530 (Wed, 17 Oct 2018)" );
	script_name( "Oracle Java SE Security Updates-05 (oct2018-4428296) Linux" );
	script_tag( name: "summary", value: "The host is installed with Oracle Java SE
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Check if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to errors in 'Utility'
  and 'Sound' components." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to partially access and modify data." );
	script_tag( name: "affected", value: "Oracle Java SE 11 on Linux." );
	script_tag( name: "solution", value: "Apply the appropriate patch from the vendor. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpuoct2018-4428296.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_java_prdts_detect_lin.sc" );
	script_mandatory_keys( "Oracle/Java/JDK/Linux/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
jreVer = infos["version"];
path = infos["location"];
if(version_is_equal( version: jreVer, test_version: "11" )){
	report = report_fixed_ver( installed_version: jreVer, fixed_version: "Apply the patch", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

