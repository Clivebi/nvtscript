if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818129" );
	script_version( "2021-10-05T08:17:22+0000" );
	script_cve_id( "CVE-2021-2161", "CVE-2021-2163" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-10-05 08:17:22 +0000 (Tue, 05 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-10 13:51:00 +0000 (Thu, 10 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-05-17 14:19:02 +0530 (Mon, 17 May 2021)" );
	script_name( "Oracle Java SE Security Update (apr2021) - Linux" );
	script_tag( name: "summary", value: "Oracle Java SE is prone to multiple security vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to multiple errors in
  'Libraries' component." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attacker to have an impact on integrity." );
	script_tag( name: "affected", value: "Oracle Java SE version 7u291 (1.7.0.291)
  and earlier, 8u281 (1.8.0.281) and earlier, 11.0.10 and earlier, 16 on Linux." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://www.oracle.com/security-alerts/cpuapr2021.html#AppendixJAVA" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_java_prdts_detect_lin.sc" );
	script_mandatory_keys( "Oracle/Java/JDK_or_JRE/Linux/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
CPE = "cpe:/a:oracle:jre";
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "1.8.0", test_version2: "1.8.0.281" ) || version_in_range( version: vers, test_version: "1.7.0", test_version2: "1.7.0.291" ) || version_in_range( version: vers, test_version: "11.0", test_version2: "11.0.10" ) || version_is_equal( version: vers, test_version: "16.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "Apply the patch", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

