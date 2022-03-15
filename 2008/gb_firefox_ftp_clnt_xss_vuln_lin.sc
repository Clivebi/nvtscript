if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800043" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2008-10-24 15:11:55 +0200 (Fri, 24 Oct 2008)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2008-4723" );
	script_bugtraq_id( 31855 );
	script_name( "Firefox Web Browser FTP Client XSS Vulnerability (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_lin.sc" );
	script_mandatory_keys( "Firefox/Linux/Ver" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/31855/exploit" );
	script_tag( name: "impact", value: "Successful remote attack result in injection of arbitrary web
  script or HTML code." );
	script_tag( name: "affected", value: "Firefox version 3.0.1 to 3.0.3 on Linux." );
	script_tag( name: "insight", value: "The flaw is due to the way browser handles web script or html via
  ftp:// URL for an html document within a JPG, PDF, or TXT files." );
	script_tag( name: "solution", value: "Upgrade to Firefox version 3.6.3 or later." );
	script_tag( name: "summary", value: "The host is installed with Mozilla Firefox browser and is prone
  to Cross Site Scripting (XSS) Vulnerability." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
vers = get_kb_item( "Firefox/Linux/Ver" );
if(!vers){
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "3.0.1", test_version2: "3.0.3" )){
	report = report_fixed_ver( installed_version: vers, vulnerable_range: "3.0.1 - 3.0.3" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

