if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802516" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2011-3650", "CVE-2011-3648" );
	script_bugtraq_id( 50595, 50593 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2011-11-14 13:23:08 +0530 (Mon, 14 Nov 2011)" );
	script_name( "Mozilla Products XSS and Memory Corruption Vulnerabilities (MAC OS X)" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2011/mfsa2011-49.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2011/mfsa2011-47.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Mac/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to inject arbitrary web script
  or HTML via crafted text with Shift JIS encoding and cause a denial of
  service." );
	script_tag( name: "affected", value: "Thunderbird version prior to 3.1.16, 5.0 through 7.0
  Mozilla Firefox version prior to 3.6.24, 4.x through 7.0" );
	script_tag( name: "insight", value: "The flaws are due to

  - Error, while handling invalid sequences in the Shift-JIS encoding.

  - Crash, when using Firebug to profile a JavaScript file with many functions." );
	script_tag( name: "summary", value: "The host is installed with Mozilla firefox/thunderbird and is prone
  to cross site scripting and memory corruption vulnerabilities." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 8.0 or 3.6.24 or later, Upgrade to Thunderbird version to 8.0 or 3.1.16 or later." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
vers = get_kb_item( "Mozilla/Firefox/MacOSX/Version" );
if(vers){
	if(version_is_less( version: vers, test_version: "3.6.24" ) || version_in_range( version: vers, test_version: "4.0", test_version2: "7.0" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
vers = get_kb_item( "Thunderbird/MacOSX/Version" );
if(vers){
	if(version_is_less( version: vers, test_version: "3.1.16" ) || version_in_range( version: vers, test_version: "4.0", test_version2: "7.0" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

