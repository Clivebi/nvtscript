CPE = "cpe:/a:trend_micro:office_scan";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809141" );
	script_version( "$Revision: 12149 $" );
	script_cve_id( "CVE-2016-1223" );
	script_bugtraq_id( 91288 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-29 11:48:30 +0100 (Mon, 29 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-08-22 15:40:21 +0530 (Mon, 22 Aug 2016)" );
	script_name( "Trend Micro OfficeScan Path Traversal and HTTP Header Injection Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Trend Micro
  OfficeScan and is prone to a path traversal and HTTP header injection
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to unintended file access
  and potential script execution." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to cause path traversal and HTTP header injection vulnerabilities." );
	script_tag( name: "affected", value: "Trend Micro OfficeScan versions prior to 11.0.6077." );
	script_tag( name: "solution", value: "Upgrade to  OfficeScan Corp. 11.0 Service Pack 1
  Critical Patch build 6077." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://esupport.trendmicro.com/solution/ja-JP/1114102.aspx" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_trend_micro_office_scan_detect.sc" );
	script_mandatory_keys( "Trend/Micro/Officescan/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!trendVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( trendVer, "^11\\." )){
	if(version_is_less( version: trendVer, test_version: "11.0.6077" )){
		report = report_fixed_ver( installed_version: trendVer, fixed_version: "11.0.6077" );
		security_message( data: report );
		exit( 0 );
	}
}

