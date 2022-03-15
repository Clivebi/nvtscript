if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902209" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-07-02 08:02:13 +0200 (Fri, 02 Jul 2010)" );
	script_cve_id( "CVE-2010-1206" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Mozilla Firefox Address Bar Spoofing Vulnerability june-10 (Windows)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to conduct spoofing attacks." );
	script_tag( name: "affected", value: "Firefox version before 3.6.6." );
	script_tag( name: "insight", value: "The flaw is due to error in the 'startDocumentLoad()' function in
  'browser/base/content/browser.js', fails to implement Same Origin Policy.
  This can be exploited to display arbitrary content in the blank document
  while showing the URL of a trusted web site in the address bar." );
	script_tag( name: "solution", value: "Upgrade to Firefox version 3.6.6 or later." );
	script_tag( name: "summary", value: "The host is installed with Mozilla Firefox and is prone to spoofing
  vulnerability." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/40283" );
	script_xref( name: "URL", value: "http://hg.mozilla.org/mozilla-central/rev/cadddabb1178" );
	script_xref( name: "URL", value: "http://lcamtuf.blogspot.com/2010/06/yeah-about-that-address-bar-thing.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
ffVer = get_kb_item( "Firefox/Win/Ver" );
if(ffVer){
	if(version_is_less( version: ffVer, test_version: "3.6.6" )){
		report = report_fixed_ver( installed_version: ffVer, fixed_version: "3.6.6" );
		security_message( port: 0, data: report );
	}
}

