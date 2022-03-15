CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817211" );
	script_version( "2021-10-05T11:36:17+0000" );
	script_cve_id( "CVE-2020-12415", "CVE-2020-12416", "CVE-2020-12417", "CVE-2020-12418", "CVE-2020-12419", "CVE-2020-12420", "CVE-2020-12402", "CVE-2020-12421", "CVE-2020-12422", "CVE-2020-12423", "CVE-2020-12424", "CVE-2020-12425", "CVE-2020-12426" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-27 02:15:00 +0000 (Mon, 27 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-07-02 10:56:32 +0530 (Thu, 02 Jul 2020)" );
	script_name( "Mozilla Firefox Security Update (mfsa2020-24) - Mac OS X" );
	script_tag( name: "summary", value: "Mozilla Firefox is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - AppCache manifest poisoning due to url encoded character processing.

  - Use-after-free in WebRTC VideoBroadcaster.

  - Memory corruption due to missing sign-extension for ValueTags on ARM64.

  - Information disclosure due to manipulated URL object.

  - Use-after-free in nsGlobalWindowInner.

  - Use-After-Free when trying to connect to a STUN server.

  - RSA Key Generation vulnerable to side-channel attack.

  - Add-On updates did not respect the same certificate trust rules as software updates.

  - Integer overflow in nsJPEGEncoder::emptyOutputBuffer.

  - DLL Hijacking due to searching %PATH% for a library.

  - WebRTC permission prompt could have been bypassed by a compromised content process.

  - Out of bound read in Date.parse().

  - Memory safety bugs fixed in Firefox 78." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to conduct a denial-of-service, execute arbitrary code or information disclosure
  on affected system." );
	script_tag( name: "affected", value: "Mozilla Firefox version before 78." );
	script_tag( name: "solution", value: "Update to Mozilla Firefox version 78
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2020-24/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
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
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "78.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "78.0", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

