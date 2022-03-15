if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801329" );
	script_version( "$Revision: 11553 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-22 16:22:01 +0200 (Sat, 22 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2010-05-13 09:36:55 +0200 (Thu, 13 May 2010)" );
	script_cve_id( "CVE-2010-1851" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_name( "Google Chrome Cross Site Data Leakage Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://www.cnet.com/8301-31361_1-20004265-254.html" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.com/2010/01/stable-channel-update_25.html" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (c) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_portable_win.sc" );
	script_mandatory_keys( "GoogleChrome/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will let the remote web servers to
identify specific persons and their product searches via 'HTTP' request login." );
	script_tag( name: "affected", value: "Google Chrome version 4.0.249.78 and proir on Windows." );
	script_tag( name: "insight", value: "The flaw is due to an error in handling background 'HTTP' requests.
It uses cookies in possibly unexpected manner when the 'Invisible Hand extension'
is enabled." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with Google Chrome Web Browser and is
prone to cross site data leakage vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("version_func.inc.sc");
gcVer = get_kb_item( "GoogleChrome/Win/Ver" );
if(!gcVer){
	exit( 0 );
}
if(version_is_less_equal( version: gcVer, test_version: "4.0.249.78" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}
exit( 99 );

