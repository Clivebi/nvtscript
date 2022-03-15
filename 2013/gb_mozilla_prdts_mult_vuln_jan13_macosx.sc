if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803099" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2013-0744", "CVE-2013-0746", "CVE-2013-0748", "CVE-2013-0750", "CVE-2013-0753", "CVE-2013-0754", "CVE-2013-0758", "CVE-2013-0759" );
	script_bugtraq_id( 57218, 57238, 57234, 57235, 57209, 57217, 57232, 57228 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-01-16 15:29:04 +0530 (Wed, 16 Jan 2013)" );
	script_name( "Mozilla Products Multiple Vulnerabilities January13 (Mac OS X)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/51752/" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1027955" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1027957" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1027958" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2013/mfsa2013-04.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2013/mfsa2013-05.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2013/mfsa2013-09.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2013/mfsa2013-11.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2013/mfsa2013-12.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2013/mfsa2013-15.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2013/mfsa2013-16.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2013/mfsa2013-17.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to inject scripts, bypass
  certain security restrictions, execute arbitrary code or crash the
  application in the context of the browser." );
	script_tag( name: "affected", value: "SeaMonkey version before 2.15 on Mac OS X

  Thunderbird version before 17.0.2 on Mac OS X

  Mozilla Firefox version before 18.0 on Mac OS X

  Thunderbird ESR version 10.x before 10.0.12 and 17.x before 17.0.2 on Mac OS X

  Mozilla Firefox ESR version 10.x before 10.0.12 and 17.x before 17.0.2 on Mac OS X" );
	script_tag( name: "insight", value: "- URL spoofing in address bar during page loads in conjunction with a
    204 (aka No Content) HTTP status code.

  - Improper interaction between plugin objects and SVG elements.

  - Use-after-free error exists within the implementation serializeToStream
    in the XMLSerializer component and ListenerManager, and in the function
   'TableBackgroundPainter::TableBackgroundData::Destroy'.
    'serializeToStream' implementation in the XMLSerializer component

  - Compartment mismatch with quickstubs returned values.

  - An error within the 'XBL.__proto__.toString()' can be exploited to
    disclose the address space layout." );
	script_tag( name: "summary", value: "This host is installed with Mozilla Firefox/Thunderbird/Seamonkey and is
  prone to multiple vulnerabilities." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 18.0 or ESR version 10.0.12 or 17.0.2 or later, upgrade to SeaMonkey version to 2.15 or later,
  upgrade to Thunderbird version to 17.0.2 or ESR 10.0.12 or 17.0.2 or later." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
vers = get_kb_item( "Mozilla/Firefox/MacOSX/Version" );
esrvers = get_kb_item( "Mozilla/Firefox-ESR/MacOSX/Version" );
if(vers || esrvers){
	if(version_is_less( version: vers, test_version: "18.0" ) || version_in_range( version: esrvers, test_version: "10.0", test_version2: "10.0.11" ) || version_in_range( version: esrvers, test_version: "17.0", test_version2: "17.0.1" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
vers = get_kb_item( "SeaMonkey/MacOSX/Version" );
if(vers){
	if(version_is_less( version: vers, test_version: "2.15" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
vers = get_kb_item( "Thunderbird/MacOSX/Version" );
esrvers = get_kb_item( "Thunderbird-ESR/MacOSX/Version" );
if(vers || esrvers){
	if(version_is_less( version: vers, test_version: "17.0.2" ) || version_in_range( version: esrvers, test_version: "10.0", test_version2: "10.0.11" ) || version_in_range( version: esrvers, test_version: "17.0", test_version2: "17.0.1" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

