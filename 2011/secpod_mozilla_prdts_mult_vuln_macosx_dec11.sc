if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902778" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_cve_id( "CVE-2011-3660", "CVE-2011-3661", "CVE-2011-3663", "CVE-2011-3665" );
	script_bugtraq_id( 51133, 51135, 51136, 51134 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "creation_date", value: "2011-12-22 12:14:45 +0530 (Thu, 22 Dec 2011)" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_name( "Mozilla Products Multiple Vulnerabilities - Dec 11 (MAC OS X)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/47302/" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2011/mfsa2011-53.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2011/mfsa2011-54.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2011/mfsa2011-56.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2011/mfsa2011-58.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to execute arbitrary code in the
  context of the affected application. Failed exploit attempts will likely
  result in denial-of-service conditions." );
	script_tag( name: "affected", value: "SeaMonkey version before 2.6
  Thunderbird version 5.0 through 8.0
  Mozilla Firefox version Firefox 4.x through 8.0" );
	script_tag( name: "insight", value: "Multiple flaws are due to

  - Unspecified errors in browser engine.

  - An error exists within the YARR regular expression library when parsing
    javascript content.

  - Not properly handling SVG animation accessKey events when JavaScript is
    disabled. This can lead to the user's key strokes being leaked.

  - An error exists within the handling of OGG <video> elements." );
	script_tag( name: "summary", value: "The host is installed with Mozilla firefox/thunderbird/seamonkey and is
  prone multiple vulnerabilities." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 9.0 or later, Upgrade to SeaMonkey version to 2.6 or later,
  Upgrade to Thunderbird version to 9.0 or later." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
vers = get_kb_item( "Mozilla/Firefox/MacOSX/Version" );
if(vers){
	if(version_in_range( version: vers, test_version: "4.0", test_version2: "8.0" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "4.0 - 8.0" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
vers = get_kb_item( "SeaMonkey/MacOSX/Version" );
if(vers){
	if(version_is_less( version: vers, test_version: "2.6" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "2.6" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
vers = get_kb_item( "Thunderbird/MacOSX/Version" );
if(vers){
	if(version_in_range( version: vers, test_version: "5.0", test_version2: "8.0" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "5.0 - 8.0" );
		security_message( port: 0, data: report );
	}
}

