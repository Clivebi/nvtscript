if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802832" );
	script_version( "$Revision: 11549 $" );
	script_cve_id( "CVE-2011-4690" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-22 14:11:10 +0200 (Sat, 22 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2012-04-09 16:39:39 +0530 (Mon, 09 Apr 2012)" );
	script_name( "Opera Cache History Information Disclosure Vulnerability (Linux)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/47128" );
	script_xref( name: "URL", value: "http://lcamtuf.coredump.cx/cachetime/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_opera_detection_linux_900037.sc" );
	script_mandatory_keys( "Opera/Linux/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to gain sensitive
information about visited web page." );
	script_tag( name: "affected", value: "Opera version 11.60 and prior on Linux" );
	script_tag( name: "insight", value: "The flaw is due to an improper capturing of data about the times
of same origin policy violations during IFRAME and image loading attempts,
allows attacker to enumerate visited sites via crafted JavaScript code." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is installed with Opera and is prone to information
disclosure vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("version_func.inc.sc");
operaVer = get_kb_item( "Opera/Linux/Version" );
if(!operaVer){
	exit( 0 );
}
if(version_is_less_equal( version: operaVer, test_version: "11.60" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

