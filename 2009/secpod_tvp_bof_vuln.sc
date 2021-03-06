if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900454" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-02-02 05:02:24 +0100 (Mon, 02 Feb 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-0261" );
	script_bugtraq_id( 33373 );
	script_name( "Total Video Player Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/7839" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_tvp_detect.sc" );
	script_mandatory_keys( "TotalVideo/Player/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker execute arbitrary codes in the
  context of the application and can cause stack overflow to make the resource
  unavailable." );
	script_tag( name: "affected", value: "Total Video Player version 1.31 and prior on Windows." );
	script_tag( name: "insight", value: "This flaw is due to improper boundary check at 'DefaultSkin.ini' in the
  ColumnHeaderSpan value which copies data to an insufficiently sized memory
  buffer." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with Total Video Player and is prone to
  Buffer Overflow vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("version_func.inc.sc");
tvpVer = get_kb_item( "TotalVideo/Player/Ver" );
if(!tvpVer){
	exit( 0 );
}
if(version_is_less_equal( version: tvpVer, test_version: "1.31" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

