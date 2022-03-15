if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815183" );
	script_version( "2021-09-08T08:01:40+0000" );
	script_cve_id( "CVE-2019-2745" );
	script_tag( name: "cvss_base", value: "1.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-08 08:01:40 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 13:00:00 +0000 (Tue, 08 Sep 2020)" );
	script_tag( name: "creation_date", value: "2019-07-17 13:09:32 +0530 (Wed, 17 Jul 2019)" );
	script_name( "Oracle Java SE Security Updates (jul2019-5072835) 05 - Windows" );
	script_tag( name: "summary", value: "The host is installed with Oracle Java SE
  and is prone to a security vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to error in 'Security'
  component." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to have an impact on confidentiality." );
	script_tag( name: "affected", value: "Oracle Java SE version 1.7.0 to 1.7.0.221,
  1.8.0 to 1.8.0.212 and 11.0 to 11.0.3 on Windows." );
	script_tag( name: "solution", value: "Apply the appropriate patch from the vendor. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.oracle.com/technetwork/security-advisory/cpujul2019-5072835.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_java_prdts_detect_win.sc" );
	script_mandatory_keys( "Sun/Java/JDK_or_JRE/Win/installed" );
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
if(version_in_range( version: vers, test_version: "1.7.0", test_version2: "1.7.0.221" ) || version_in_range( version: vers, test_version: "1.8.0", test_version2: "1.8.0.212" ) || version_in_range( version: vers, test_version: "11.0", test_version2: "11.0.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "Apply the patch", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

