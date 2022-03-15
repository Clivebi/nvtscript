if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902027" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-03-23 15:59:14 +0100 (Tue, 23 Mar 2010)" );
	script_cve_id( "CVE-2010-1028" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Mozilla Firefox Unspecified Vulnerability (Windows)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow the attackers to execute arbitrary code." );
	script_tag( name: "affected", value: "Mozilla Firefox 3.6 and prior" );
	script_tag( name: "insight", value: "The flaw is caused by unspecified errors and unknown attack vectors." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 3.6.3 or later" );
	script_tag( name: "summary", value: "The host is running Mozilla Firefox and is prone to unspecified
  vulnerability." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/38608" );
	script_xref( name: "URL", value: "http://www.h-online.com/security/news/item/Zero-day-exploit-for-Firefox-3-6-936124.html" );
	script_xref( name: "URL", value: "http://blog.psi2.de/en/2010/02/20/going-commercial-with-firefox-vulnerabilities/comment-page-1/#comment-666" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
foxVer = get_kb_item( "Firefox/Win/Ver" );
if(!foxVer){
	exit( 0 );
}
if(version_is_less_equal( version: foxVer, test_version: "3.6" )){
	report = report_fixed_ver( installed_version: foxVer, vulnerable_range: "Less than or equal to 3.6" );
	security_message( port: 0, data: report );
}

