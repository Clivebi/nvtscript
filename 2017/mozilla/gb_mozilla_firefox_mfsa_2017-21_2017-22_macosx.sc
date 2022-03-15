CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811850" );
	script_version( "2021-09-17T09:09:50+0000" );
	script_cve_id( "CVE-2017-7793", "CVE-2017-7818", "CVE-2017-7819", "CVE-2017-7824", "CVE-2017-7812", "CVE-2017-7814", "CVE-2017-7813", "CVE-2017-7825", "CVE-2017-7815", "CVE-2017-7816", "CVE-2017-7821", "CVE-2017-7823", "CVE-2017-7822", "CVE-2017-7820", "CVE-2017-7811", "CVE-2017-7810", "CVE-2017-7805" );
	script_bugtraq_id( 101055, 101053, 101059, 101057, 101054 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-17 09:09:50 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-07-30 16:56:00 +0000 (Mon, 30 Jul 2018)" );
	script_tag( name: "creation_date", value: "2017-10-03 15:34:48 +0530 (Tue, 03 Oct 2017)" );
	script_name( "Mozilla Firefox Security Updates(mfsa_2017-21_2017-22)-MAC OS X" );
	script_tag( name: "summary", value: "This host is installed with
  Mozilla Firefox and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Use-after-free error in with Fetch API.

  - Use-after-free error in during ARIA array manipulation.

  - Use-after-free error in while resizing images in design mode.

  - Buffer overflow error in when drawing and validating elements with ANGLE.

  - Use-after-free error in TLS 1.2 generating handshake hashes.

  - Drag and drop of malicious page content to the tab bar can open locally stored files.

  - Blob and data URLs bypass phishing and malware protection warnings.

  - Integer truncation in the JavaScript parser.

  - OS X fonts render some Tibetan and Arabic unicode characters as spaces.

  - Spoofing attack with modal dialogs on non-e10s installations.

  - Web Extensions can load about: URLs in extension UI.

  - Web Extensions can download and open non-executable files without user interaction.

  - CSP sandbox directive did not create a unique origin.

  - Web Crypto allows AES-GCM with 0-length IV.

  - Xray wrapper bypass with new tab and web console.

  - Memory safety bugs fixed in Firefox 56." );
	script_tag( name: "impact", value: "Successful exploitation of these
  vulnerabilities will allow remote attackers to cause denial of service, conduct
  spoofing attack, obtain sensitive information and execute arbitrary code." );
	script_tag( name: "affected", value: "Mozilla Firefox version before
  56.0 on MAC OS X." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 56.0
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2017-21" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Mozilla/Firefox/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
ffVer = infos["version"];
ffPath = infos["location"];
if(version_is_less( version: ffVer, test_version: "56.0" )){
	report = report_fixed_ver( installed_version: ffVer, fixed_version: "56.0", install_path: ffPath );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

