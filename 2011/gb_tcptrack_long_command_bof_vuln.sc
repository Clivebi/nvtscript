if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801973" );
	script_version( "2020-04-23T08:43:39+0000" );
	script_tag( name: "last_modification", value: "2020-04-23 08:43:39 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2011-09-13 07:51:43 +0200 (Tue, 13 Sep 2011)" );
	script_cve_id( "CVE-2011-2903" );
	script_bugtraq_id( 49352 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Tcptrack Command Line Parsing Heap Based Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://seclists.org/oss-sec/2011/q3/293" );
	script_xref( name: "URL", value: "https://bugs.gentoo.org/show_bug.cgi?id=377917" );
	script_xref( name: "URL", value: "http://www.rhythm.cx/~steve/devel/tcptrack/#news" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "gb_tcptrack_detect.sc" );
	script_family( "Buffer overflow" );
	script_mandatory_keys( "Tcptrack/Ver" );
	script_tag( name: "impact", value: "Successful exploitation allows attackers to execute arbitrary code via a long
  command line argument in the LWRES dissector when processing malformed data
  or packets." );
	script_tag( name: "affected", value: "Tcptrack version prior to 1.4.2" );
	script_tag( name: "insight", value: "The flaw is caused  due to error in command line parsing, it is not properly
  handling long command line argument." );
	script_tag( name: "solution", value: "Upgrade to Tcptrack 1.4.2 or later." );
	script_tag( name: "summary", value: "This host is installed with Tcptrack and is prone to heap based
  buffer overflow vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.rhythm.cx/~steve/devel/tcptrack/#gettingit" );
	exit( 0 );
}
require("version_func.inc.sc");
tcpVer = get_kb_item( "Tcptrack/Ver" );
if(!tcpVer){
	exit( 0 );
}
if(version_is_less( version: tcpVer, test_version: "1.4.2" )){
	report = report_fixed_ver( installed_version: tcpVer, fixed_version: "1.4.2" );
	security_message( port: 0, data: report );
}

