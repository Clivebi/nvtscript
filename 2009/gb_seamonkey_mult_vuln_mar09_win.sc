if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800365" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2009-03-10 11:59:23 +0100 (Tue, 10 Mar 2009)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-0771", "CVE-2009-0772", "CVE-2009-0773", "CVE-2009-0774", "CVE-2009-0775", "CVE-2009-0776", "CVE-2009-0777" );
	script_bugtraq_id( 33990 );
	script_name( "Mozilla Seamonkey Multiple Vulnerabilities Mar-09 (Windows)" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2009/mfsa2009-07.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2009/mfsa2009-08.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2009/mfsa2009-09.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2009/mfsa2009-11.html" );
	script_xref( name: "URL", value: "http://downloads.securityfocus.com/vulnerabilities/exploits/33969.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_seamonkey_detect_win.sc" );
	script_mandatory_keys( "Seamonkey/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will let attacker execute arbitrary code in the
  context of an affected web application or can cause URL address bar
  spoofing attacks or may cause denial of service." );
	script_tag( name: "affected", value: "Seamonkey version prior to 1.1.15 on Windows." );
	script_tag( name: "insight", value: "Multiple flaws due to:

  - Layout engine error which causes memory corruption and assertion failures.

  - Layout engine error related to 'nsCSSStyleSheet::GetOwnerNode', events and
    garage collection which triggers memory corruption.

  - Layout engine error through a splice of an array that contains 'non-set'
    elements which causes 'jsarray.cpp' to pass an incorrect argument to the
    'ResizeSlots' function which causes application crash.

  - Vectors related to js_DecompileValueGenerator, jsopcode.cpp,
    __defineSetter__ and watch which causes a segmentation fault.

  - Layout engine error in the vector related to 'gczeal'.

  - Double free vulnerability in Seamonkey via 'cloned XUL DOM elements' which
    were linked as a parent and child are not properly handled during garbage
    collection which causes arbitrary code execution.

  - 'nsIRDFService' in Seamonkey allows to bypass the same origin policy and
    read XML data through another domain by cross-domain redirect.

  - Error while decoding invisible characters when they are displayed in the
    location bar which causes incorrect address to be displayed in the URL bar
    and causes spoofing attacks." );
	script_tag( name: "solution", value: "Upgrade to Seamonkey version 1.1.15." );
	script_tag( name: "summary", value: "The host is installed with Mozilla Seamonkey browser and is prone
  to multiple vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
smVer = get_kb_item( "Seamonkey/Win/Ver" );
if(!smVer){
	exit( 0 );
}
if(version_is_less( version: smVer, test_version: "1.1.15" )){
	report = report_fixed_ver( installed_version: smVer, fixed_version: "1.1.15" );
	security_message( port: 0, data: report );
}

