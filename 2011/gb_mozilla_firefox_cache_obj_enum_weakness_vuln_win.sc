if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802547" );
	script_version( "$Revision: 11997 $" );
	script_cve_id( "CVE-2011-4688" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-12-09 17:47:27 +0530 (Fri, 09 Dec 2011)" );
	script_name( "Mozilla Firefox Cache Objects History Enumeration Weakness Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/47090" );
	script_xref( name: "URL", value: "http://lcamtuf.coredump.cx/cachetime/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation allows remote attackers to extraction
browser history by observing cache timing via crafted JavaScript code." );
	script_tag( name: "affected", value: "Mozilla Firefox versions 8.0.1 and prior on Windows." );
	script_tag( name: "insight", value: "The flaw is caused due an error in handling cache objects and
can be exploited to enumerate visited sites." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is installed with Mozilla Firefox and is prone to cache
objects history enumeration weakness vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("version_func.inc.sc");
ffVer = get_kb_item( "Firefox/Win/Ver" );
if(ffVer){
	if(version_is_less_equal( version: ffVer, test_version: "8.0.1" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

