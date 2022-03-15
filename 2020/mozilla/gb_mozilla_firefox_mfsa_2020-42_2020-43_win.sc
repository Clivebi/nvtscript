CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817500" );
	script_version( "2021-08-17T06:00:55+0000" );
	script_cve_id( "CVE-2020-15675", "CVE-2020-15677", "CVE-2020-15676", "CVE-2020-15678", "CVE-2020-15673", "CVE-2020-15674" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-17 06:00:55 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-02 19:21:00 +0000 (Fri, 02 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-09-23 12:27:23 +0530 (Wed, 23 Sep 2020)" );
	script_name( "Mozilla Firefox Security Update (mfsa_2020-42_2020-43) - Windows" );
	script_tag( name: "summary", value: "Mozilla Firefox is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Use-After-Free in WebGL.

  - Download origin spoofing via redirect.

  - XSS when pasting attacker-controlled data into a contenteditable element.

  - When recursing through layers while scrolling, an iterator may have become
    invalid, resulting in a potential use-after-free scenario." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to conduct a denial-of-service, execute arbitrary code or information disclosure
  on affected system." );
	script_tag( name: "affected", value: "Mozilla Firefox version before 81 on Windows." );
	script_tag( name: "solution", value: "Update to Mozilla Firefox version 81
  or later, Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2020-42/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_win.sc", "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "81" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "81", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

