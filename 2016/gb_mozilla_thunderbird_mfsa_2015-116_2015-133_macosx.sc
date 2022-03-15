CPE = "cpe:/a:mozilla:thunderbird";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807636" );
	script_version( "2021-09-09T12:52:45+0000" );
	script_cve_id( "CVE-2015-7181", "CVE-2015-7182", "CVE-2015-7183", "CVE-2015-7197", "CVE-2015-7198", "CVE-2015-7199", "CVE-2015-7200", "CVE-2015-7194", "CVE-2015-7193", "CVE-2015-7189", "CVE-2015-7188", "CVE-2015-4513", "CVE-2015-4514" );
	script_bugtraq_id( 77416, 77415, 77411 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-09 12:52:45 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-04-06 16:24:49 +0530 (Wed, 06 Apr 2016)" );
	script_name( "Mozilla Thunderbird Security Update (mfsa_2015-116_2015-133) - Mac OS X" );
	script_tag( name: "summary", value: "Mozilla Thunderbird is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An improper handling of the CORS cross-origin request algorithm when
    non-standard Content-Type headers are received.

  - A heap Buffer Overflow in nsJPEGEncoder during image interactions in canvas.

  - An insufficient validation of IP address string.

  - Multiple unspecified vulnerabilities in the browser engine.

  - A buffer overflow vulnerability in the rx::TextureStorage11 class in ANGLE.

  - Lack of status checking in 'AddWeightedPathSegLists' and
    'SVGPathSegListSMILType::Interpolate' functions.

  - Missing status check in CryptoKey interface implementation.

  - A memory corruption vulnerability in libjar through zip files.

  - Memory corruption issues in NSS and NSPR.

  - A heap-based buffer overflow in the ASN.1 decoder in Mozilla (NSS).

  - An integer overflow in the PL_ARENA_ALLOCATE implementation in Mozilla (NSS)" );
	script_tag( name: "impact", value: "Successful exploitation of this
  vulnerability will allow remote attackers to bypass security restrictions,
  to execute arbitrary code and to cause denial of service." );
	script_tag( name: "affected", value: "Mozilla Thunderbird versions before 38.4." );
	script_tag( name: "solution", value: "Update to version 38.4 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-133/" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-132/" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-131/" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-128/" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-127/" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-123/" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-122/" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-116/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Thunderbird/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "38.4" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "38.4", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

