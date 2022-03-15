if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113073" );
	script_version( "2021-09-10T08:01:37+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 08:01:37 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-12-21 11:48:49 +0100 (Thu, 21 Dec 2017)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:25:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2017-16578", "CVE-2017-16579", "CVE-2017-16580", "CVE-2017-16581", "CVE-2017-16582", "CVE-2017-16583", "CVE-2017-16584", "CVE-2017-16585", "CVE-2017-16586", "CVE-2017-16587" );
	script_name( "Foxit Reader <= 8.3.2 Multiple Vulnerabilities - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_foxit_reader_detect_portable_win.sc" );
	script_mandatory_keys( "foxit/reader/ver" );
	script_tag( name: "summary", value: "Foxit Reader is prone to multiple code execution and information
  disclosure vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Foxit Reader allows information disclosure through improper
  validation of user input. It also allows code execution via both improper object validation and
  improper user input validation that leads to a type confusion condition." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to access
  sensitive information or execute code on the target host." );
	script_tag( name: "affected", value: "Foxit Reader 8.3.2 and prior." );
	script_tag( name: "solution", value: "Update to version 9.0 or later." );
	script_xref( name: "URL", value: "https://www.foxitsoftware.com/support/security-bulletins.php" );
	script_xref( name: "URL", value: "https://www.foxitsoftware.com/de/pdf-reader/version-history.php" );
	exit( 0 );
}
CPE = "cpe:/a:foxitsoftware:reader";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
path = infos["location"];
if(version_is_less_equal( version: version, test_version: "8.3.2.25013" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.0", install_path: path );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

