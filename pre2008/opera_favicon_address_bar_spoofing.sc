if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14245" );
	script_version( "2020-04-27T11:01:03+0000" );
	script_tag( name: "last_modification", value: "2020-04-27 11:01:03 +0000 (Mon, 27 Apr 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2004-0537" );
	script_bugtraq_id( 10452 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_name( "Opera web browser address bar spoofing weakness (2)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "Windows" );
	script_dependencies( "gb_opera_detect_portable_win.sc" );
	script_mandatory_keys( "Opera/Win/Version" );
	script_tag( name: "solution", value: "Install to Opera 7.51 or newer." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "The remote host contains a web browser that is vulnerable to
  address bar spoofing attacks.

  Description :
  The remote host is using Opera, an alternative web browser.
  This version of Opera is vulnerable to a security weakness that may
  permit malicious web pages to spoof address bar information.  It is
  reported that the 'favicon' feature can be used to spoof the domain of
  a malicious web page.  An attacker can create an icon that includes
  the text of the desired site and is similar to the way Opera displays
  information in the address bar.  The attacker can then obfuscate the
  real address with spaces.

  This issue can be used to spoof information in the address bar, page
  bar and page/window cycler." );
	script_xref( name: "URL", value: "http://www.greymagic.com/security/advisories/gm007-op/" );
	script_xref( name: "URL", value: "http://www.opera.com/windows/changelogs/751/" );
	exit( 0 );
}
require("version_func.inc.sc");
OperaVer = get_kb_item( "Opera/Win/Version" );
if(!OperaVer){
	exit( 0 );
}
if(version_is_less_equal( version: OperaVer, test_version: "7.50" )){
	report = report_fixed_ver( installed_version: OperaVer, vulnerable_range: "Less than or equal to 7.50" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

