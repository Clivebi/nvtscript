if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800031" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2008-10-17 14:35:03 +0200 (Fri, 17 Oct 2008)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2008-4582" );
	script_bugtraq_id( 31747 );
	script_name( "Firefox .url Shortcut File Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox/Win/Ver" );
	script_xref( name: "URL", value: "http://liudieyu0.blog124.fc2.com/blog-entry-6.html" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/497091/100/0/threaded" );
	script_tag( name: "impact", value: "Successful remote exploitation could result in disclosure of sensitive
  information." );
	script_tag( name: "affected", value: "Firefox version 3.0.1 to 3.0.3 on Windows." );
	script_tag( name: "insight", value: "The Browser does not properly identify the context of Windows .url shortcut
  files, which allows remote attackers to bypass the Same Origin Policy and
  obtain sensitive information via an HTML document that is directly accessible
  through a filesystem." );
	script_tag( name: "solution", value: "Upgrade to Firefox version 3.6.3 or later." );
	script_tag( name: "summary", value: "The host is installed with Mozilla Firefox browser, that is prone
  to information disclosure vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
vers = get_kb_item( "Firefox/Win/Ver" );
if(!vers){
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "3.0.1", test_version2: "3.0.3" )){
	report = report_fixed_ver( installed_version: vers, vulnerable_range: "3.0.1 - 3.0.3" );
	security_message( port: 0, data: report );
}

