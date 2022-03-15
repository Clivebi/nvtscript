if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900513" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-02-26 05:27:20 +0100 (Thu, 26 Feb 2009)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_cve_id( "CVE-2009-0652" );
	script_bugtraq_id( 33837 );
	script_name( "Firefox URL Spoofing And Phising Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://www.mozilla.org/projects/security/tld-idn-policy-list.html" );
	script_xref( name: "URL", value: "http://www.blackhat.com/html/bh-dc-09/bh-dc-09-speakers.html#Marlinspike" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox/Win/Ver" );
	script_tag( name: "impact", value: "Successful remote exploitation will let the attacker spoof the URL
  information by using homoglyphs of say the /(slash) and ?(question mark)and
  can gain sensitive information by redirecting the user to any malicious URL." );
	script_tag( name: "affected", value: "Mozilla Firefox version 3.0.6 and prior on Windows." );
	script_tag( name: "insight", value: "Firefox doesn't properly prevent the literal rendering of homoglyph
  characters in IDN domain names. This renders the user vulnerable to URL
  spoofing and phising attacks as the atatcker may redirect the user to a
  different arbitrary malformed website." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 3.6.3 or later" );
	script_tag( name: "summary", value: "The host is installed with Mozilla Firefox browser and is prone
  to URL spoofing and phising vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
firefoxVer = get_kb_item( "Firefox/Win/Ver" );
if(!firefoxVer){
	exit( 0 );
}
if(version_is_less_equal( version: firefoxVer, test_version: "3.0.6" )){
	report = report_fixed_ver( installed_version: firefoxVer, vulnerable_range: "Less than or equal to 3.0.6" );
	security_message( port: 0, data: report );
}

