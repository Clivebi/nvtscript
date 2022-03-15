if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800057" );
	script_version( "2020-04-27T11:04:25+0000" );
	script_tag( name: "last_modification", value: "2020-04-27 11:04:25 +0000 (Mon, 27 Apr 2020)" );
	script_tag( name: "creation_date", value: "2008-11-21 14:18:03 +0100 (Fri, 21 Nov 2008)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2008-5012", "CVE-2008-5013", "CVE-2008-5014", "CVE-2008-5015", "CVE-2008-5016", "CVE-2008-5017", "CVE-2008-5018", "CVE-2008-5019", "CVE-2008-5021", "CVE-2008-5022", "CVE-2008-5023", "CVE-2008-5024", "CVE-2008-5052", "CVE-2008-0017" );
	script_bugtraq_id( 32281 );
	script_name( "Mozilla Firefox Multiple Vulnerabilities November-08 (Windows)" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2008/mfsa2008-47.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2008/mfsa2008-48.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2008/mfsa2008-49.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2008/mfsa2008-50.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2008/mfsa2008-51.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2008/mfsa2008-52.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2008/mfsa2008-53.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2008/mfsa2008-54.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2008/mfsa2008-55.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2008/mfsa2008-56.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2008/mfsa2008-57.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2008/mfsa2008-58.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could result in remote arbitrary code execution,
  bypass security restrictions, spoofing attacks, sensitive information
  disclosure, and JavaScript code that can be executed with the privileges of the signed user." );
	script_tag( name: "affected", value: "Firefox version prior to 2.0.0.18 and 3.x to 3.0.3 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Firefox version 2.0.0.18 or 3.0.4." );
	script_tag( name: "summary", value: "The host is installed with Mozilla Firefox browser and is prone
  to multiple vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
ffVer = get_kb_item( "Firefox/Win/Ver" );
if(!ffVer){
	exit( 0 );
}
if(version_is_less( version: ffVer, test_version: "2.0.0.18" )){
	report = report_fixed_ver( installed_version: ffVer, fixed_version: "2.0.0.18" );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(version_in_range( version: ffVer, test_version: "3.0", test_version2: "3.0.3" )){
	report = report_fixed_ver( installed_version: ffVer, vulnerable_range: "3.0 - 3.0.3" );
	security_message( port: 0, data: report );
}

