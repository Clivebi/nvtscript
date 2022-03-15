if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801089" );
	script_version( "$Revision: 11554 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-22 17:11:42 +0200 (Sat, 22 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2009-12-14 09:18:47 +0100 (Mon, 14 Dec 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-4265" );
	script_name( "IDEAL Administration '.ipj' File Processing Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://freetexthost.com/abydoz3jwu" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/37572" );
	script_xref( name: "URL", value: "http://pocoftheday.blogspot.com/2009/12/ideal-administration-2009-v97-local.html" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_ideal_administrator_detect.sc" );
	script_mandatory_keys( "IDEAL/Admin/Ver" );
	script_tag( name: "affected", value: "IDEAL Administration 9.7.1 and prior." );
	script_tag( name: "insight", value: "This flaw is due to a boundary error in the processing of Ideal Project
  Files ('.ipj'). This can be exploited to cause a stack based buffer overflow
  when a user is tricked into opening a specially crafted '.ipj' file through
  the application." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with IDEAL Administration and is prone to
  Buffer Overflow Vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker execute arbitrary code or
  compromise a user's system." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("version_func.inc.sc");
if(iaVer = get_kb_item( "IDEAL/Admin/Ver" )){
	if(version_is_less_equal( version: iaVer, test_version: "9.7.1" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

