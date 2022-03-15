if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803018" );
	script_version( "2019-07-17T11:14:11+0000" );
	script_cve_id( "CVE-2012-3965", "CVE-2012-3973" );
	script_bugtraq_id( 55249 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)" );
	script_tag( name: "creation_date", value: "2012-08-30 15:19:59 +0530 (Thu, 30 Aug 2012)" );
	script_name( "Mozilla Firefox Multiple Vulnerabilities - August12 (Mac OS X)" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1027450" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1027451" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-60.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-66.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Mozilla/Firefox/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to inject scripts, bypass
  certain security restrictions, execute arbitrary code in the context of the
  browser." );
	script_tag( name: "affected", value: "Mozilla Firefox version before 15.0 on Mac OS X" );
	script_tag( name: "insight", value: "- An error due to improper restriction of navigation to the about:newtab
    page, which allows remote attackers to execute arbitrary JavaScript code
    with chrome privileges via a crafted web site that triggers creation of a
    new tab and then a new window.

  - An error in the debugger in the developer-tools subsystem fails to
    restrict access to the remote-debugging service when remote debugging
    is disabled and the experimental HTTPMonitor extension has been installed
    and enabled." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 15.0 or later." );
	script_tag( name: "summary", value: "This host is installed with Mozilla Firefox and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
ffVer = get_kb_item( "Mozilla/Firefox/MacOSX/Version" );
if(ffVer){
	if(version_is_less( version: ffVer, test_version: "10.0" ) || version_in_range( version: ffVer, test_version: "11.0", test_version2: "14.0" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

