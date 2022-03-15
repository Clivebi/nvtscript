CPE = "cpe:/a:mozilla:thunderbird";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805527" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-0816", "CVE-2015-0815", "CVE-2015-0807", "CVE-2015-0801" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-04-06 15:37:24 +0530 (Mon, 06 Apr 2015)" );
	script_name( "Mozilla Thunderbird Multiple Vulnerabilities-01 Apr15 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Mozilla
  Thunderbird and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Improper restriction of resource: URLs.

  - Multiple unspecified errors.

  - An error in 'navigator.sendBeacon' implementation.

  - An error allowing to bypass the Same Origin Policy." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary JavaScript code, conduct cross-site request
  forgery (CSRF) attacks, conduct denial of service (memory corruption and
  application crash) attack and possibly execute arbitrary code." );
	script_tag( name: "affected", value: "Mozilla Thunderbird before version 31.6
  on Mac OS X" );
	script_tag( name: "solution", value: "Upgrade to Mozilla Thunderbird version
  31.6 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-33" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-30" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-37" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-40" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Thunderbird/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "31.6" )){
	report = "Installed version: " + vers + "\n" + "Fixed version:     31.6\n";
	security_message( data: report );
	exit( 0 );
}

