if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818172" );
	script_version( "2021-08-26T14:01:06+0000" );
	script_cve_id( "CVE-2021-2388" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 14:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-26 17:05:00 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-28 23:46:29 +0530 (Wed, 28 Jul 2021)" );
	script_name( "Oracle Java SE Security Update (jul2021) 02 - Linux" );
	script_tag( name: "summary", value: "This host is missing a security update
  according to Oracle." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to multiple errors in
  'Libraries' and 'Networking' components." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attacker to have an impact on integrity, availability and confidentiality." );
	script_tag( name: "affected", value: "Oracle Java SE version 8u291 (1.8.0.291) and
  earlier, 11.0.11 and earlier, 16.0.1 and earlier on Linux." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://www.oracle.com/security-alerts/cpujul2021.html#AppendixJAVA" );
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
if(version_in_range( version: vers, test_version: "1.8.0", test_version2: "1.8.0.291" ) || version_in_range( version: vers, test_version: "11.0", test_version2: "11.0.11" ) || version_in_range( version: vers, test_version: "16.0", test_version2: "16.0.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "Apply the patch", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

