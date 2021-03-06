if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802395" );
	script_version( "$Revision: 11549 $" );
	script_cve_id( "CVE-2012-1003" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-22 14:11:10 +0200 (Sat, 22 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2012-02-08 16:13:59 +0530 (Wed, 08 Feb 2012)" );
	script_name( "Opera Large Integer Argument Denial of Service Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/73027" );
	script_xref( name: "URL", value: "http://blog.vulnhunt.com/index.php/2012/02/02/cal-2012-0004-opera-array-integer-overflow/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_opera_detect_portable_win.sc" );
	script_mandatory_keys( "Opera/Win/Version" );
	script_tag( name: "impact", value: "Successful exploitation may allow remote attackers to cause
a denial of service via a large integer argument." );
	script_tag( name: "affected", value: "Opera version 11.60 and prior." );
	script_tag( name: "insight", value: "The flaw is due to an improper handling of argument sent to the
functions Int32Array, Float32Array, Float64Array, Uint32Array, Int16Array
or ArrayBuffer, which can be exploited to crash the Opera via a large
integer argument to these functions." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is installed with Opera and is prone to denial of
service vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("version_func.inc.sc");
operaVer = get_kb_item( "Opera/Win/Version" );
if(!operaVer){
	exit( 0 );
}
if(version_is_less_equal( version: operaVer, test_version: "11.60" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}
exit( 99 );

