if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802866" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2012-1937", "CVE-2012-1940", "CVE-2012-1944", "CVE-2012-1945", "CVE-2012-1946", "CVE-2012-1947", "CVE-2012-3105", "CVE-2012-1941", "CVE-2012-0441", "CVE-2012-1938" );
	script_bugtraq_id( 53223, 53220, 53221, 53225, 53219, 53218, 53228, 53229, 53227, 53224, 53798, 53796 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-06-19 11:31:59 +0530 (Tue, 19 Jun 2012)" );
	script_name( "Mozilla Products Multiple Vulnerabilities - June12 (Mac OS X)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/49368" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/49366" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1027120" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-34.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-36.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-37.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-38.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-40.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to inject scripts, bypass
  certain security restrictions, execute arbitrary code in the context of the
  browser or cause a denial of service." );
	script_tag( name: "affected", value: "SeaMonkey version before 2.10,
  Thunderbird version 5.0 through 12.0,
  Mozilla Firefox version 4.x through 12.0,
  Thunderbird ESR version 10.x before 10.0.5 and
  Mozilla Firefox ESR version 10.x before 10.0.5 on Mac OS X" );
	script_tag( name: "insight", value: "- Multiple unspecified errors in browser engine can be exploited to corrupt
    memory.

  - Multiple use-after-free errors exist in 'nsFrameList::FirstChild' when
    handling column layouts with absolute positioning within a container that
    changes the size.

  - The improper implementation of Content Security Policy inline-script
    blocking feature, fails to block inline event handlers such as onclick.

  - An error when loading HTML pages from Windows shares, which can be
    exploited to disclose files from local resources via an iframe tag.

  - An error exists within 'utf16_to_isolatin1' function when converting
    from unicode to native character sets.

  - An error in 'nsHTMLReflowState::CalculateHypotheticalBox' when a window is
    resized on a page with nested columns using absolute and relative
    positioning.

  - The glBufferData function in the WebGL implementation, fails to mitigate
    an unspecified flaw in an NVIDIA driver." );
	script_tag( name: "summary", value: "This host is installed with Mozilla firefox/thunderbird/seamonkey and is prone
  to multiple vulnerabilities." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 13.0 or ESR version 10.0.5 or later, upgrade to SeaMonkey version to 2.10 or later,
  upgrade to Thunderbird version to 13.0 or ESR 10.0.5 or later." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
vers = get_kb_item( "Mozilla/Firefox/MacOSX/Version" );
if(vers){
	if(version_in_range( version: vers, test_version: "4.0", test_version2: "10.0.4" ) || version_in_range( version: vers, test_version: "11.0", test_version2: "12.0" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
vers = get_kb_item( "SeaMonkey/MacOSX/Version" );
if(vers){
	if(version_is_less( version: vers, test_version: "2.10" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
vers = get_kb_item( "Thunderbird/MacOSX/Version" );
if(vers){
	if(version_in_range( version: vers, test_version: "5.0", test_version2: "10.0.4" ) || version_in_range( version: vers, test_version: "11.0", test_version2: "12.0" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

