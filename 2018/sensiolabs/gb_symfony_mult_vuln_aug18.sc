if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113246" );
	script_version( "2021-06-03T02:00:18+0000" );
	script_tag( name: "last_modification", value: "2021-06-03 02:00:18 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-08-07 12:27:08 +0200 (Tue, 07 Aug 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-13 17:56:00 +0000 (Wed, 13 Mar 2019)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2017-16653", "CVE-2017-16654", "CVE-2017-16790" );
	script_name( "Symfony <= 2.7.37, 2.8.* <= 2.8.30, 3.* <= 3.2.13 and 3.3.* <= 3.3.12 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_symfony_consolidation.sc" );
	script_mandatory_keys( "symfony/detected" );
	script_tag( name: "summary", value: "Symfony is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - An attacker can use the locale parameter to naivate to arbitrary directions.

  - An attacker can insert a file path into the 'FileType' POST parameter
      to retrieve the contents of that file.

  - The CSRF protection doesn't use different tokens for HTTP and HTTPS,
      allowing for MITM attacks on HTTP that can then be used in an HTTPS context." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to obtain sensitive information." );
	script_tag( name: "affected", value: "Symfony through version 2.7.37, 2.8.0 through 2.8.30, 3.0.0 through 3.2.13
  and 3.3.0 through 3.3.12." );
	script_tag( name: "solution", value: "Update to version 2.7.38, 2.8.31, 3.2.14 or 3.3.13 respectively." );
	script_xref( name: "URL", value: "https://symfony.com/blog/cve-2017-16653-csrf-protection-does-not-use-different-tokens-for-http-and-https" );
	script_xref( name: "URL", value: "https://symfony.com/blog/cve-2017-16790-ensure-that-submitted-data-are-uploaded-files" );
	exit( 0 );
}
CPE = "cpe:/a:sensiolabs:symfony";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "2.7.38" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.7.38" );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "2.8.0", test_version2: "2.8.30" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.8.31" );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "3.0.0", test_version2: "3.2.13" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.2.14" );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "3.3.0", test_version2: "3.3.12" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.3.13" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

