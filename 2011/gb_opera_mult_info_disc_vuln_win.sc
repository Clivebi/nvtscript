if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802363" );
	script_version( "2019-09-16T06:54:58+0000" );
	script_cve_id( "CVE-2010-5072", "CVE-2010-5068" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-09-16 06:54:58 +0000 (Mon, 16 Sep 2019)" );
	script_tag( name: "creation_date", value: "2011-12-09 16:10:28 +0530 (Fri, 09 Dec 2011)" );
	script_name( "Opera Multiple Information Disclosure Vulnerabilities (Windows)" );
	script_xref( name: "URL", value: "http://w2spconf.com/2010/papers/p26.pdf" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_opera_detect_portable_win.sc" );
	script_mandatory_keys( "Opera/Win/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to gain
  sensitive information about visited web pages by calling getComputedStyle method or via a
  crafted HTML document." );
	script_tag( name: "affected", value: "Opera version 10.50 on Windows." );
	script_tag( name: "insight", value: "Multiple flaws are due to implementation errors in,

  - The JavaScript failing to restrict the set of values contained in the
  object returned by the getComputedStyle method.

  - The Cascading Style Sheets (CSS) failing to handle the visited
  pseudo-class." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is installed with Opera and is prone to multiple
  information disclosure vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("version_func.inc.sc");
operaVer = get_kb_item( "Opera/Win/Version" );
if(!operaVer){
	exit( 0 );
}
if(version_is_equal( version: operaVer, test_version: "10.50" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}
exit( 99 );

