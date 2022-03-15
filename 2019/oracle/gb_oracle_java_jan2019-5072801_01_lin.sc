if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814914" );
	script_version( "2021-09-07T14:01:38+0000" );
	script_cve_id( "CVE-2018-11212", "CVE-2019-2426", "CVE-2019-2422" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 14:01:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-07 20:15:00 +0000 (Thu, 07 Jan 2021)" );
	script_tag( name: "creation_date", value: "2019-01-16 12:38:57 +0530 (Wed, 16 Jan 2019)" );
	script_name( "Oracle Java SE Multiple Vulnerabilities(Jan2019-5072801)-Linux" );
	script_tag( name: "summary", value: "The host is installed with Oracle Java SE
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to errors in
  'ImageIO', 'Networking' and  'Libraries' components." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackes
  to partially cause denial of service and access data." );
	script_tag( name: "affected", value: "Oracle Java SE version 1.7.0 to 1.7.0.201,
  1.8.0 to 1.8.0.192 and 11.0.1 on Linux." );
	script_tag( name: "solution", value: "Apply the appropriate patch from the vendor. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://www.oracle.com/technetwork/security-advisory/cpujan2019-5072801.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_java_prdts_detect_lin.sc" );
	script_mandatory_keys( "Oracle/Java/JDK_or_JRE/Linux/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/a:oracle:jre",
	 "cpe:/a:sun:jre" );
if(!infos = get_app_version_and_location_from_list( cpe_list: cpe_list, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "1.7.0", test_version2: "1.7.0.201" ) || version_in_range( version: vers, test_version: "1.8.0", test_version2: "1.8.0.192" ) || version_in_range( version: vers, test_version: "11.0", test_version2: "11.0.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "Apply the patch", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

