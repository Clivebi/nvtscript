if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801347" );
	script_version( "$Revision: 12653 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $" );
	script_tag( name: "creation_date", value: "2010-06-04 09:43:24 +0200 (Fri, 04 Jun 2010)" );
	script_cve_id( "CVE-2010-2117" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_name( "Mozilla Firefox 'IFRAME' Denial Of Service vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://websecurity.com.ua/4238/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/511509/100/0/threaded" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2010 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to cause a
denial of service." );
	script_tag( name: "affected", value: "Firefox version 3.0.x prior to 3.0.19, 3.5.x prior to 3.5.9,
3.6.x prior to 3.6.3" );
	script_tag( name: "insight", value: "The flaw is due to improper handling of 'JavaScript' code which
contains an infinite loop, that creates IFRAME elements for invalid news://
or nntp:// URIs." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is installed with Mozilla Firefox browser and is prone
to Denial of Service vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("version_func.inc.sc");
ffVer = get_kb_item( "Firefox/Win/Ver" );
if(ffVer){
	if(version_in_range( version: ffVer, test_version: "3.5", test_version2: "3.5.9" ) || version_in_range( version: ffVer, test_version: "3.0", test_version2: "3.0.19" ) || version_in_range( version: ffVer, test_version: "3.6", test_version2: "3.6.3" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

