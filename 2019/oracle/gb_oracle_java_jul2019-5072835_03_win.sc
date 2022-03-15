if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815177" );
	script_version( "2021-09-07T14:01:38+0000" );
	script_cve_id( "CVE-2019-2769", "CVE-2019-2762", "CVE-2019-2766", "CVE-2019-7317", "CVE-2019-2816" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-07 14:01:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 13:00:00 +0000 (Tue, 08 Sep 2020)" );
	script_tag( name: "creation_date", value: "2019-07-17 13:09:55 +0530 (Wed, 17 Jul 2019)" );
	script_name( "Oracle Java SE Security Updates (jul2019-5072835) 03 - Windows" );
	script_tag( name: "summary", value: "The host is installed with Oracle Java SE
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to errors in
  'AWT (libpng)', 'Utilities' and 'Networking' components." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attacker to have an impact on confidentiality, integrity and availability." );
	script_tag( name: "affected", value: "Oracle Java SE version 7u221(1.7.0.221) and
  earlier, 8u212(1.8.0.212) and earlier, 11.0.2 and earlier, 12.0.1 and earlier
  on Windows." );
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
if(version_in_range( version: vers, test_version: "1.7.0", test_version2: "1.7.0.221" ) || version_in_range( version: vers, test_version: "1.8.0", test_version2: "1.8.0.212" ) || version_in_range( version: vers, test_version: "11.0", test_version2: "11.0.3" ) || version_in_range( version: vers, test_version: "12.0", test_version2: "12.0.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "Apply the patch", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

