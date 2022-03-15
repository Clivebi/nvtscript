CPE = "cpe:/a:apple:itunes";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810526" );
	script_version( "2021-09-08T10:01:41+0000" );
	script_cve_id( "CVE-2017-2354", "CVE-2017-2355", "CVE-2017-2356", "CVE-2017-2366" );
	script_bugtraq_id( 95736, 95733 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-08 10:01:41 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-08 21:33:00 +0000 (Fri, 08 Mar 2019)" );
	script_tag( name: "creation_date", value: "2017-01-30 13:20:32 +0530 (Mon, 30 Jan 2017)" );
	script_name( "Apple iTunes Multiple Code Execution Vulnerabilities Jan17 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Apple iTunes
  and is prone to multiple code execution vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to multiple memory
  corruption and initialization errors." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code. Failed exploit attempts may result in a
  denial-of-service condition." );
	script_tag( name: "affected", value: "Apple iTunes versions before 12.5.5
  on Windows." );
	script_tag( name: "solution", value: "Upgrade to Apple iTunes 12.5.5 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT207486" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_apple_itunes_detection_win_900123.sc" );
	script_mandatory_keys( "iTunes/Win/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "12.5.5" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "12.5.5", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

