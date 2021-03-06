if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802212" );
	script_version( "2019-07-17T11:14:11+0000" );
	script_tag( name: "last_modification", value: "2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)" );
	script_tag( name: "creation_date", value: "2011-07-07 15:43:33 +0200 (Thu, 07 Jul 2011)" );
	script_cve_id( "CVE-2011-2598", "CVE-2011-2367", "CVE-2011-2368", "CVE-2011-2369" );
	script_bugtraq_id( 48319, 48371, 48375, 48379 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Mozilla Firefox Multiple Vulnerabilities July-11 (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/44972/" );
	script_xref( name: "URL", value: "http://www.contextis.com/resources/blog/webgl2/" );
	script_xref( name: "URL", value: "http://blog.mozilla.com/security/2011/06/16/webgl-graphics-memory-stealing-issue/" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation allows remote attackers to disclose potentially
  sensitive information, conduct cross-site scripting attacks, and compromise
  a user's system." );
	script_tag( name: "affected", value: "Mozilla Firefox versions 4.x through 4.0.1" );
	script_tag( name: "insight", value: "- An error within WebGL allows remote attackers to obtain screenshots of the
    windows of arbitrary desktop applications via vectors involving an SVG
    filter, an IFRAME element, and uninitialized data in graphics memory.

  - An error within WebGL when reading certain data can be exploited to
    disclose GPU memory contents used by other processes.

  - An error within WebGL can be exploited to execute arbitrary code or
    cause a denial of service.

  - Input passed via HTML-encoded entities is not properly decoded before
    being displayed inside SVG elements, which allows remote attackers to
    inject arbitrary web script or HTML." );
	script_tag( name: "solution", value: "Upgrade to Firefox version 5.0 or later." );
	script_tag( name: "summary", value: "The host is installed with Mozilla Firefox and is prone to multiple
  vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
ffVer = get_kb_item( "Firefox/Win/Ver" );
if(ffVer){
	if(version_in_range( version: ffVer, test_version: "4.0", test_version2: "4.0.1" ) || version_in_range( version: ffVer, test_version: "4.0.b1", test_version2: "4.0.b12" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

