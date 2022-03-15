if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802753" );
	script_version( "2020-10-19T15:33:20+0000" );
	script_cve_id( "CVE-2011-1337", "CVE-2011-2609", "CVE-2011-2610", "CVE-2011-2611", "CVE-2011-2612", "CVE-2011-2613", "CVE-2011-2614", "CVE-2011-2615", "CVE-2011-2616", "CVE-2011-2617", "CVE-2011-2618", "CVE-2011-2619", "CVE-2011-2620", "CVE-2011-2621", "CVE-2011-2622", "CVE-2011-2623", "CVE-2011-2624", "CVE-2011-2625", "CVE-2011-2626", "CVE-2011-2627" );
	script_bugtraq_id( 48501, 48500, 48556 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-19 15:33:20 +0000 (Mon, 19 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-04-19 10:01:43 +0530 (Thu, 19 Apr 2012)" );
	script_name( "Opera Browser Multiple Vulnerabilities July-11 (Mac OS X)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/45060" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/68323" );
	script_xref( name: "URL", value: "http://www.opera.com/docs/changelogs/mac/1150/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_opera_detect_macosx.sc" );
	script_mandatory_keys( "Opera/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary code
  and cause a denial of service." );
	script_tag( name: "affected", value: "Opera Web Browser version prior 11.50 on Mac OS X" );
	script_tag( name: "insight", value: "Please see the references for more information on the vulnerabilities." );
	script_tag( name: "solution", value: "Upgrade to Opera Web Browser version 11.50 or later." );
	script_tag( name: "summary", value: "The host is installed with Opera browser and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
operaVer = get_kb_item( "Opera/MacOSX/Version" );
if(!operaVer){
	exit( 0 );
}
if(version_is_less( version: operaVer, test_version: "11.50" )){
	report = report_fixed_ver( installed_version: operaVer, fixed_version: "11.50" );
	security_message( port: 0, data: report );
}

