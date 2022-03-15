CPE = "cpe:/a:apple:safari";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807889" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2016-4618", "CVE-2016-4751", "CVE-2016-4728", "CVE-2016-4758", "CVE-2016-4611", "CVE-2016-4729", "CVE-2016-4730", "CVE-2016-4731", "CVE-2016-4734", "CVE-2016-4735", "CVE-2016-4737", "CVE-2016-4759", "CVE-2016-4762", "CVE-2016-4766", "CVE-2016-4767", "CVE-2016-4768", "CVE-2016-4769", "CVE-2016-4760", "CVE-2016-4733", "CVE-2016-4765", "CVE-2016-4763" );
	script_bugtraq_id( 93053, 93057, 93067, 93066, 93065, 93064, 93062, 93058 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-09-28 12:58:27 +0530 (Wed, 28 Sep 2016)" );
	script_name( "Apple Safari Multiple Vulnerabilities September16 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Apple Safari
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A state management issue in the handling of tab sessions.

  - Multiple input validation issues.

  - A parsing issue in the handling of error prototypes.

  - A permissions issue in the handling of the location variable.

  - Multiple memory corruption issues.

  - An error in safari's support of HTTP/0.9.

  - A certificate validation issue in the handling of WKWebView." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct cross-site scripting attacks, spoofing attacks, arbitrary
  code execution, access to potentially sensitive data, intercept and alter
  network traffic." );
	script_tag( name: "affected", value: "Apple Safari versions before 10" );
	script_tag( name: "solution", value: "Upgrade to Apple Safari version 10 or
  later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT207157" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "macosx_safari_detect.sc" );
	script_mandatory_keys( "AppleSafari/MacOSX/Version" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!safVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: safVer, test_version: "10" )){
	report = report_fixed_ver( installed_version: safVer, fixed_version: "10" );
	security_message( data: report );
	exit( 0 );
}

