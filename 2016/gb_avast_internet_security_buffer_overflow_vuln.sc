CPE = "cpe:/a:avast:avast_internet_security";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808055" );
	script_version( "2021-09-17T13:01:55+0000" );
	script_cve_id( "CVE-2015-8620" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-17 13:01:55 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-26 20:37:00 +0000 (Fri, 26 Mar 2021)" );
	script_tag( name: "creation_date", value: "2016-06-03 18:38:06 +0530 (Fri, 03 Jun 2016)" );
	script_name( "Avast Internet Security Heap-Based Buffer Overflow Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Avast Internet
  Security and is prone to heap-based buffer overflow vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists in avast virtualization
  driver (aswSnx.sys) that handles 'Sandbox' and 'DeepScreen' functionality
  improperly." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to elevate privileges from any account type and execute code as SYSTEM." );
	script_tag( name: "affected", value: "Avast Internet Security version before
  11.1.2253" );
	script_tag( name: "solution", value: "Upgrade to Avast Internet Security
  version 11.1.2253 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2016/Feb/94" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_avast_internet_security_detect.sc" );
	script_mandatory_keys( "Avast/Internet-Security/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!avastVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: avastVer, test_version: "11.1.2253" )){
	report = report_fixed_ver( installed_version: avastVer, fixed_version: "11.1.2253" );
	security_message( data: report );
	exit( 0 );
}
