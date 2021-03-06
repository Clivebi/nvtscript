if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900448" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-01-28 13:27:12 +0100 (Wed, 28 Jan 2009)" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:N" );
	script_cve_id( "CVE-2008-5913" );
	script_bugtraq_id( 33276 );
	script_name( "Firefox Information Disclosure Vulnerability Jan09 (Windows)" );
	script_xref( name: "URL", value: "http://www.trusteer.com/files/In-session-phishing-advisory-2.pdf" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker execute arbitrary
  codes in the context of the web browser and can obtain sensitive information
  of the remote user through the web browser." );
	script_tag( name: "affected", value: "Mozilla Firefox version from 2.0 to 3.0.5 on Windows." );
	script_tag( name: "insight", value: "The Web Browser fails to properly enforce the same-origin policy, which leads
  to cross-domain information disclosure." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 3.6.3 or later." );
	script_tag( name: "summary", value: "The host is installed with Mozilla Firefox browser and is prone
  to information disclosure vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
firefoxVer = get_kb_item( "Firefox/Win/Ver" );
if(!firefoxVer){
	exit( 0 );
}
if(version_in_range( version: firefoxVer, test_version: "2.0", test_version2: "3.0.5" )){
	report = report_fixed_ver( installed_version: firefoxVer, vulnerable_range: "2.0 - 3.0.5" );
	security_message( port: 0, data: report );
}

