CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805523" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-0816", "CVE-2015-0815", "CVE-2015-0814", "CVE-2015-0812", "CVE-2015-0811", "CVE-2015-0810", "CVE-2015-0808", "CVE-2015-0807", "CVE-2015-0806", "CVE-2015-0805", "CVE-2015-0804", "CVE-2015-0803", "CVE-2015-0802", "CVE-2015-0801" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-04-06 15:05:42 +0530 (Mon, 06 Apr 2015)" );
	script_name( "Mozilla Firefox Multiple Vulnerabilities-01 Apr15 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Mozilla
  Firefox and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Improper restriction of resource: URLs.

  - Multiple unspecified errors.

  - No HTTPS session for lightweight theme add-on installations .

  - An out of bounds read error in the QCMS color management library.

  - An error that is triggered when handling specially crafted flash content,
  which can cause the cursor to become invisible.

  - An incorrect memory management for simple-type arrays in WebRTC.

  - An error in 'navigator.sendBeacon' implementation.

  - Two errors in 'Off Main Thread Compositing' implementation.

  - Two use-after-free errors in 'HTMLSourceElement::AfterSetAttr' function.

  - An error allowing to bypass the Same Origin Policy.

  - Use of docshell type information instead of page principal information for
  'Window.webidl' access control." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary JavaScript code, conduct denial of service
  (memory corruption and application crash) attack, possibly execute arbitrary
  code, conduct DNS spoofing attack and conduct cross-site request forgery
  (CSRF) attacks." );
	script_tag( name: "affected", value: "Mozilla Firefox before version 37.0 on
  Mac OS X" );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 37.0
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-33" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-30" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-32" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-34" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-35" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-36" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-37" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-38" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-39" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-42" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-40" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Mozilla/Firefox/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!ffVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: ffVer, test_version: "37.0" )){
	report = "Installed version: " + ffVer + "\n" + "Fixed version:     " + "37.0" + "\n";
	security_message( data: report );
	exit( 0 );
}

