if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900439" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-01-22 12:00:13 +0100 (Thu, 22 Jan 2009)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:S/C:N/I:P/A:N" );
	script_cve_id( "CVE-2008-5915" );
	script_bugtraq_id( 33276 );
	script_name( "Google Chrome Information Disclosure Vulnerability" );
	script_xref( name: "URL", value: "http://www.trusteer.com/files/In-session-phishing-advisory-2.pdf" );
	script_xref( name: "URL", value: "http://www.darkreading.com/security/attacks/showArticle.jhtml?articleID=212900161" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_google_chrome_detect_portable_win.sc" );
	script_mandatory_keys( "GoogleChrome/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker execute arbitrary codes in
  the context of the web browser and can reveal sensitive information of the
  remote user through the web browser." );
	script_tag( name: "affected", value: "Google Chrome version 1.0.154.43 and prior." );
	script_tag( name: "insight", value: "This flaw is due to cross-domain information disclosure vulnerability as
  the web browser fails to properly enforce the same-origin policy." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with Google Chrome and is prone to
  information disclosure vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.com" );
	exit( 0 );
}
require("version_func.inc.sc");
chromeVer = get_kb_item( "GoogleChrome/Win/Ver" );
if(!chromeVer){
	exit( 0 );
}
if(version_is_less_equal( version: chromeVer, test_version: "1.0.154.43" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}
exit( 99 );

