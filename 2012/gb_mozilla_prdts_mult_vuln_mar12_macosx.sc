if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802821" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2012-0461", "CVE-2012-0463", "CVE-2012-0458", "CVE-2012-0457", "CVE-2012-0455", "CVE-2012-0464", "CVE-2012-0456" );
	script_bugtraq_id( 52464, 52466, 52460, 52459, 52458, 52465, 52461 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-03-19 17:59:17 +0530 (Mon, 19 Mar 2012)" );
	script_name( "Mozilla Products Multiple Vulnerabilities - Mar12 (Mac OS X)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/48402" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-13.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-14.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-16.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-19.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to cause a denial of service or
  possibly execute arbitrary code via unknown vectors." );
	script_tag( name: "affected", value: "SeaMonkey version before 2.8
  Thunderbird ESR version 10.x before 10.0.3
  Mozilla Firefox ESR version 10.x before 10.0.3
  Thunderbird version before 3.1.20 and 5.0 through 10.0
  Mozilla Firefox version before 3.6.28 and 4.x through 10.0" );
	script_tag( name: "insight", value: "The flaws are due to

  - Multiple unspecified vulnerabilities in the browser engine.

  - An improper implementation of the nsWindow failing to validate an instance
    after event dispatching.

  - An error when handling 'javascript:'.

  - A use-after-free error exists within the
    'nsSMILTimeValueSpec::ConvertBetweenTimeContainers()' function.

  - An improper implementation of SVG Filters." );
	script_tag( name: "summary", value: "The host is installed with Mozilla firefox/thunderbird/seamonkey and is prone
  to multiple vulnerabilities." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 3.6.28 or 11.0 or later, upgrade to SeaMonkey version to 2.8 or later,
  upgrade to Thunderbird version to 3.1.20 or 11 or later." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
vers = get_kb_item( "Mozilla/Firefox/MacOSX/Version" );
if(vers){
	if(version_is_less( version: vers, test_version: "3.6.28" ) || version_in_range( version: vers, test_version: "4.0", test_version2: "10.0.2" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
vers = get_kb_item( "SeaMonkey/MacOSX/Version" );
if(vers){
	if(version_is_less( version: vers, test_version: "2.8" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
vers = get_kb_item( "Thunderbird/MacOSX/Version" );
if(vers){
	if(version_is_less( version: vers, test_version: "3.1.20" ) || version_in_range( version: vers, test_version: "5.0", test_version2: "10.0.2" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

