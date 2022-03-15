CPE = "cpe:/a:oracle:jre";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812638" );
	script_version( "2021-08-20T14:11:31+0000" );
	script_cve_id( "CVE-2018-2582", "CVE-2018-2639", "CVE-2018-2638", "CVE-2018-2627" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-20 14:11:31 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 12:29:00 +0000 (Tue, 08 Sep 2020)" );
	script_tag( name: "creation_date", value: "2018-01-17 11:39:21 +0530 (Wed, 17 Jan 2018)" );
	script_name( "Oracle Java SE Security Updates (jan2018-3236628) 02 - Windows" );
	script_tag( name: "summary", value: "The host is installed with Oracle Java SE
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to

  - Multiple errors in the Deployment component.

  - An error in the Installer component.

  - An error in Hotspot component." );
	script_tag( name: "impact", value: "Successful exploitation of this vulnerability
  will allow remote attackers to gain elevated privileges and modify user data." );
	script_tag( name: "affected", value: "Oracle Java SE version 1.8.0.152 and earlier,
  9.0.1 and earlier on Windows" );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_java_prdts_detect_portable_win.sc" );
	script_mandatory_keys( "Sun/Java/JRE/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
jreVer = infos["version"];
path = infos["location"];
if(IsMatchRegexp( jreVer, "^((1\\.8)|(9))" )){
	if(version_in_range( version: jreVer, test_version: "1.8.0", test_version2: "1.8.0.152" ) || version_in_range( version: jreVer, test_version: "9.0", test_version2: "9.0.1" )){
		report = report_fixed_ver( installed_version: jreVer, fixed_version: "Apply the patch", install_path: path );
		security_message( data: report );
		exit( 0 );
	}
}
exit( 0 );

