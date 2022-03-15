CPE = "cpe:/a:apple:itunes";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807890" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2016-4728", "CVE-2016-4758", "CVE-2016-4759", "CVE-2016-4762", "CVE-2016-4766", "CVE-2016-4767", "CVE-2016-4768", "CVE-2016-4760", "CVE-2016-4765", "CVE-2016-4763", "CVE-2016-4769" );
	script_bugtraq_id( 93064, 93066, 93067, 93062 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-09-28 15:03:42 +0530 (Wed, 28 Sep 2016)" );
	script_name( "Apple iTunes Multiple Vulnerabilities Sep16 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Apple iTunes
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - A parsing issue in the handling of error prototypes.

  - A permissions issue in the handling of the location variable.

  - Multiple memory corruption issues.

  - Cross-protocol exploitation of non-HTTP services using DNS rebinding.

  - A certificate validation issue in the handling of WKWebView." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code, intercept and alter network traffic, access
  non-HTTP services and gain access to potentially sensitive information." );
	script_tag( name: "affected", value: "Apple iTunes versions before 12.5.1
  on Windows." );
	script_tag( name: "solution", value: "Upgrade to Apple iTunes 12.5.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT207158" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
if(version_is_less( version: vers, test_version: "12.5.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "12.5.1", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

