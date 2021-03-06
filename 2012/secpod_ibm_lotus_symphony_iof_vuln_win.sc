if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902808" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_cve_id( "CVE-2012-0192" );
	script_bugtraq_id( 51591 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-01-25 12:12:12 +0530 (Wed, 25 Jan 2012)" );
	script_name( "IBM Lotus Symphony Image Object Integer Overflow Vulnerability (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_ibm_lotus_symphony_detect_win.sc" );
	script_mandatory_keys( "IBM/Lotus/Symphony/Win/Ver" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/47245" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/51591" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/72424" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21578684" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary code in
  the context of affected applications. Failed exploit attempts will likely
  result in denial-of-service conditions." );
	script_tag( name: "affected", value: "IBM Lotus Symphony versions 3.0.0 FP3 and prior." );
	script_tag( name: "insight", value: "The flaw is due to an integer overflow error when processing embedded
  image objects. This can be exploited to cause a heap-based buffer overflow
  via a specially crafted JPEG object within a DOC file." );
	script_tag( name: "solution", value: "Upgrade to IBM Lotus Symphony version 3.0.1 or later." );
	script_tag( name: "summary", value: "This host is installed with IBM Lotus Symphony and is prone to
  integer overflow vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
version = get_kb_item( "IBM/Lotus/Symphony/Win/Ver" );
if(version_is_less( version: version, test_version: "3.0.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.0.1" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

