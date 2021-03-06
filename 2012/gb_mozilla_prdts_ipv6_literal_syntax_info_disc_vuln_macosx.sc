if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802583" );
	script_version( "2019-07-17T11:14:11+0000" );
	script_cve_id( "CVE-2011-3670" );
	script_bugtraq_id( 51786 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)" );
	script_tag( name: "creation_date", value: "2012-02-03 17:51:59 +0530 (Fri, 03 Feb 2012)" );
	script_name( "Mozilla Products IPv6 Literal Syntax Cross Domain Information Disclosure Vulnerability (MAC OS X)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/47839/" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1026613" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-02.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to get sensitive information." );
	script_tag( name: "affected", value: "SeaMonkey version before 2.4
  Thunderbird version before 3.1.18 and 5.0 through 6.0.
  Mozilla Firefox version before 3.6.26 and 4.x through 6.0" );
	script_tag( name: "insight", value: "The flaw is due to requests made using IPv6 syntax using XMLHttpRequest
  objects through a proxy may generate errors depending on proxy configuration
  for IPv6. The resulting error messages from the proxy may disclose sensitive
  data." );
	script_tag( name: "summary", value: "The host is installed with Mozilla firefox/thunderbird/seamonkey and is prone
  to information disclosure vulnerability." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 3.6.27 or 7.0 or later.

  Upgrade to SeaMonkey version to 2.4 or later.

  Upgrade to Thunderbird version to 3.1.18 or 7.0 or later." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
ffVer = get_kb_item( "Mozilla/Firefox/MacOSX/Version" );
if(!isnull( ffVer )){
	if(version_is_less( version: ffVer, test_version: "3.6.26" ) || version_in_range( version: ffVer, test_version: "4.0", test_version2: "6.0" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
seaVer = get_kb_item( "SeaMonkey/MacOSX/Version" );
if(!isnull( seaVer )){
	if(version_is_less( version: seaVer, test_version: "2.4" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
tbVer = get_kb_item( "Thunderbird/MacOSX/Version" );
if(!isnull( tbVer )){
	if(version_is_less( version: tbVer, test_version: "3.1.18" ) || version_in_range( version: tbVer, test_version: "5.0", test_version2: "6.0" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

