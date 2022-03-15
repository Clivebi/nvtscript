CPE = "cpe:/a:mozilla:thunderbird";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812274" );
	script_version( "2021-09-17T09:09:50+0000" );
	script_cve_id( "CVE-2017-7845", "CVE-2017-7846", "CVE-2017-7847", "CVE-2017-7848", "CVE-2017-7829" );
	script_bugtraq_id( 102115, 102258 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-17 09:09:50 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-09 16:27:00 +0000 (Thu, 09 Aug 2018)" );
	script_tag( name: "creation_date", value: "2017-12-26 15:41:29 +0530 (Tue, 26 Dec 2017)" );
	script_name( "Mozilla Thunderbird Security Update (mfsa_2017-30_2017-30) - Windows" );
	script_tag( name: "summary", value: "Mozilla Thunderbird is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Buffer overflow error when drawing and validating elements with ANGLE library
    using Direct 3D 9.

  - JavaScript Execution via RSS in mailbox:// origin.

  - Local path string can be leaked from RSS feed.

  - RSS Feed vulnerable to new line Injection.

  - Mailsploit part 1: From address with encoded null character is cut off in message header display." );
	script_tag( name: "impact", value: "Successful exploitation of these
  vulnerabilities will allow remote attacker to execute arbitrary script, obtain
  sensitive information, conduct spoofing attack and cause denial of service
  condition." );
	script_tag( name: "affected", value: "Mozilla Thunderbird versions before 52.5.2." );
	script_tag( name: "solution", value: "Update to version 52.5.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2017-30" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_thunderbird_detect_portable_win.sc" );
	script_mandatory_keys( "Thunderbird/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "52.5.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "52.5.2", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

