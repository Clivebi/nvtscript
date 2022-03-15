CPE = "cpe:/a:trend_micro:business_security";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809143" );
	script_version( "2021-09-20T13:02:01+0000" );
	script_cve_id( "CVE-2016-1223", "CVE-2016-1224" );
	script_bugtraq_id( 91288, 91290 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-20 13:02:01 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-12 21:30:00 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-08-23 12:01:39 +0530 (Tue, 23 Aug 2016)" );
	script_name( "Trend Micro WFBS Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with Trend
  Micro Worry-Free Business Security and is prone to multiple
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to the
  unintended file could be accessed and potential unintended script may
  gets executed." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to cause path traversal and HTTP header injection Vulnerability and to inject
  arbitrary HTTP headers and conduct cross-site scripting (XSS)." );
	script_tag( name: "affected", value: "Trend Micro Worry-Free Business Security
  versions prior to 9.0.0.4259." );
	script_tag( name: "solution", value: "Upgrade to Trend Micro Worry-Free Business
  Security 9.0 Service Pack 3 (build 4259)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://esupport.trendmicro.com/solution/ja-JP/1114102.aspx" );
	script_xref( name: "URL", value: "http://jvn.jp/en/jp/JVN48847535/index.html" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_trend_micro_worry_free_business_security_detect.sc" );
	script_mandatory_keys( "Trend/Micro/Worry-Free/Business/Security/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!trendVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( trendVer, "^9\\." )){
	if(version_is_less( version: trendVer, test_version: "9.0.0.4259" )){
		report = report_fixed_ver( installed_version: trendVer, fixed_version: "9.0.0.4259" );
		security_message( data: report );
		exit( 0 );
	}
}

