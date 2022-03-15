if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802754" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2009-2540", "CVE-2009-1692" );
	script_bugtraq_id( 35446 );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-04-19 10:28:43 +0530 (Thu, 19 Apr 2012)" );
	script_name( "Opera Web Browser Select Object Denial Of Service Vulnerability (Mac OS X)" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/9160" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/52874" );
	script_xref( name: "URL", value: "http://www.g-sec.lu/one-bug-to-rule-them-all.html" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/504969/100/0/threaded" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_opera_detect_macosx.sc" );
	script_mandatory_keys( "Opera/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker crash the browser leading to
  denial of service." );
	script_tag( name: "affected", value: "Opera version 9.64 and prior on Mac OS X" );
	script_tag( name: "insight", value: "The flaw is due to an improper boundary check while passing data into
  the select() method and can be exploited by passing a large integer value
  resulting in memory exhaustion." );
	script_tag( name: "solution", value: "Upgrade to opera version 10 beta 1 or later." );
	script_tag( name: "summary", value: "The host is installed with Opera Web Browser and is prone to select object
  denial of service vulnerability." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
operaVer = get_kb_item( "Opera/MacOSX/Version" );
if(!operaVer){
	exit( 0 );
}
if(version_is_less_equal( version: operaVer, test_version: "9.64" )){
	report = report_fixed_ver( installed_version: operaVer, vulnerable_range: "Less than or equal to 9.64" );
	security_message( port: 0, data: report );
}

