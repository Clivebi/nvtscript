CPE = "cpe:/a:oracle:jre";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813309" );
	script_version( "2021-08-20T14:11:31+0000" );
	script_cve_id( "CVE-2018-2811" );
	script_tag( name: "cvss_base", value: "3.7" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-20 14:11:31 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 12:29:00 +0000 (Tue, 08 Sep 2020)" );
	script_tag( name: "creation_date", value: "2018-04-19 12:47:58 +0530 (Thu, 19 Apr 2018)" );
	script_name( "Oracle Java SE Security Updates (apr2018-3678067) 03 - Linux" );
	script_tag( name: "summary", value: "The host is installed with Oracle Java SE
  and is prone to a remote unspecified security vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an unspecified error
  in 'Java SE' component." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to affect confidentiality, integrity, and availability via unknown
  vectors." );
	script_tag( name: "affected", value: "Oracle Java SE version 1.8.0.162 and
  earlier, 10.0 on Linux" );
	script_tag( name: "solution", value: "Apply the appropriate patch from the vendor. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpuapr2018-3678067.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_java_prdts_detect_lin.sc" );
	script_mandatory_keys( "Sun/Java/JRE/Linux/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
jreVer = infos["version"];
path = infos["location"];
if(( IsMatchRegexp( jreVer, "^10" ) && version_is_less( version: jreVer, test_version: "10.0.1" ) ) || ( version_in_range( version: jreVer, test_version: "1.8.0", test_version2: "1.8.0.162" ) )){
	report = report_fixed_ver( installed_version: jreVer, fixed_version: "Apply the patch", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

