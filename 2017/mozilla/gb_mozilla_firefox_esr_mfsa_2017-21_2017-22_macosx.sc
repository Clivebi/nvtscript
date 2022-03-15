CPE = "cpe:/a:mozilla:firefox_esr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811851" );
	script_version( "2021-09-17T09:09:50+0000" );
	script_cve_id( "CVE-2017-7793", "CVE-2017-7818", "CVE-2017-7819", "CVE-2017-7824", "CVE-2017-7805", "CVE-2017-7814", "CVE-2017-7825", "CVE-2017-7823", "CVE-2017-7810" );
	script_bugtraq_id( 101055, 101053, 101059, 101054 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-17 09:09:50 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-01 12:05:00 +0000 (Wed, 01 Aug 2018)" );
	script_tag( name: "creation_date", value: "2017-10-04 13:06:10 +0530 (Wed, 04 Oct 2017)" );
	script_name( "Mozilla Firefox ESR Security Updates(mfsa_2017-21_2017-22)-MAC OS X" );
	script_tag( name: "summary", value: "This host is installed with
  Mozilla Firefox ESR and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Use-after-free error in with Fetch API.

  - Use-after-free error in during ARIA array manipulation.

  - Use-after-free error in while resizing images in design mode.

  - Buffer overflow error in when drawing and validating elements with ANGLE.

  - Use-after-free error in TLS 1.2 generating handshake hashes.

  - Blob and data URLs bypass phishing and malware protection warnings.

  - OS X fonts render some Tibetan and Arabic unicode characters as spaces.

  - CSP sandbox directive did not create a unique origin.

  - Memory safety bugs fixed in Firefox ESR 52.4." );
	script_tag( name: "impact", value: "Successful exploitation of these
  vulnerabilities will allow remote attackers to conduct spoofing attack,
  bypass security, execute arbitrary code and cause potentially exploitable
  crash." );
	script_tag( name: "affected", value: "Mozilla Firefox ESR version before
  52.4 on MAC OS X." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox ESR version 52.4
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2017-22" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Mozilla/Firefox-ESR/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
ffVer = infos["version"];
ffPath = infos["location"];
if(version_is_less( version: ffVer, test_version: "52.4" )){
	report = report_fixed_ver( installed_version: ffVer, fixed_version: "52.4", install_path: ffPath );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

