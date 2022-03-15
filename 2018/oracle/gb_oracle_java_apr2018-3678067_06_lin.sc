if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813312" );
	script_version( "2021-08-20T14:11:31+0000" );
	script_cve_id( "CVE-2018-2800" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-20 14:11:31 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 12:59:00 +0000 (Tue, 08 Sep 2020)" );
	script_tag( name: "creation_date", value: "2018-04-19 12:49:06 +0530 (Thu, 19 Apr 2018)" );
	script_name( "Oracle Java SE Security Updates (apr2018-3678067) 06 - Linux" );
	script_tag( name: "summary", value: "The host is installed with Oracle Java SE
  and is prone to an unspecified vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an unspecified error
  in 'RMI' component of Java SE." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to affect confidentiality and integrity via unknown vectors." );
	script_tag( name: "affected", value: "Oracle Java SE version 1.8.0.162 and earlier,
  1.7.0.171 and earlier, 1.6.0.181 and earlier on Linux." );
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
cpe_list = make_list( "cpe:/a:oracle:jre",
	 "cpe:/a:sun:jre" );
if(!infos = get_app_version_and_location_from_list( cpe_list: cpe_list, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(IsMatchRegexp( vers, "^1\\.[6-8]\\." )){
	if(( version_in_range( version: vers, test_version: "1.7.0", test_version2: "1.7.0.171" ) ) || ( version_in_range( version: vers, test_version: "1.8.0", test_version2: "1.8.0.162" ) ) || ( version_in_range( version: vers, test_version: "1.6.0", test_version2: "1.6.0.181" ) )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "Apply the patch", install_path: path );
		security_message( data: report );
		exit( 0 );
	}
}
exit( 0 );

