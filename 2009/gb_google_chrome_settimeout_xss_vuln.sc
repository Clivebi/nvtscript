if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800562" );
	script_version( "2020-12-08T12:38:13+0000" );
	script_tag( name: "last_modification", value: "2020-12-08 12:38:13 +0000 (Tue, 08 Dec 2020)" );
	script_tag( name: "creation_date", value: "2009-05-07 14:39:04 +0200 (Thu, 07 May 2009)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2009-1413" );
	script_name( "Google Chrome Timeout XSS Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/34900" );
	script_xref( name: "URL", value: "http://code.google.com/p/chromium/issues/detail?id=9860" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_google_chrome_detect_portable_win.sc" );
	script_mandatory_keys( "GoogleChrome/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker execute arbitrary
  codes and universal XSS attack in the context of the web browser." );
	script_tag( name: "affected", value: "Google Chrome version 1.0.x." );
	script_tag( name: "insight", value: "The flaw exists when javascript: URLs with unescaped spaces and
  quotes are processed and fails to cancel timeouts over a page transition thus
  enabling future code execution." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is installed with Google Chrome and is prone to XSS
  vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("version_func.inc.sc");
chromeVer = get_kb_item( "GoogleChrome/Win/Ver" );
if(!chromeVer){
	exit( 0 );
}
if(version_in_range( version: chromeVer, test_version: "1.0", test_version2: "1.0.154.59" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}
exit( 99 );

