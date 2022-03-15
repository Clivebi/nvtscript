if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803058" );
	script_version( "2020-03-20T12:10:27+0000" );
	script_cve_id( "CVE-2012-4209", "CVE-2012-4214", "CVE-2012-4215", "CVE-2012-4216", "CVE-2012-4201", "CVE-2012-4202", "CVE-2012-4207", "CVE-2012-5842", "CVE-2012-5841", "CVE-2012-5829", "CVE-2012-5830", "CVE-2012-5833", "CVE-2012-5835", "CVE-2012-5839", "CVE-2012-5840" );
	script_bugtraq_id( 56630, 56638, 56639, 56639, 56613, 56621, 56627, 56612, 56616, 56644 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-03-20 12:10:27 +0000 (Fri, 20 Mar 2020)" );
	script_tag( name: "creation_date", value: "2012-11-26 01:30:03 +0530 (Mon, 26 Nov 2012)" );
	script_name( "Mozilla Firefox Multiple Vulnerabilities-02 November12 (Mac OS X)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/51358" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1027791" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1027792" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-91.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-94.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-96.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-97.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-99.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-105.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-106.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Mozilla/Firefox/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to inject scripts, bypass
  certain security restrictions, execute arbitrary code in the context of the browser." );
	script_tag( name: "affected", value: "Mozilla Firefox version before 17.0 on Mac OS X." );
	script_tag( name: "insight", value: "Multiple error exists

  - When combining SVG text with the setting of CSS properties.

  - Within the 'copyTexImage2D' implementation in the WebGL subsystem and
  in the XrayWrapper implementation.

  - Within 'str_unescape' in the Javascript engin and in 'XMLHttpRequest'
  objects created within sandboxes." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 17.0 or later." );
	script_tag( name: "summary", value: "This host is installed with Mozilla Firefox and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
ffVer = get_kb_item( "Mozilla/Firefox/MacOSX/Version" );
if(ffVer){
	if(version_is_less( version: ffVer, test_version: "17.0" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

