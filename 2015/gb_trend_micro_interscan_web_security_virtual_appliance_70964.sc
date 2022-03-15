CPE = "cpe:/a:trendmicro:interscan_web_security_virtual_appliance";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105247" );
	script_bugtraq_id( 70964 );
	script_cve_id( "CVE-2014-8510" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_version( "2020-07-07T12:31:23+0000" );
	script_name( "Trend Micro InterScan Web Security Virtual Appliance Multiple Information Disclosure Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/70964" );
	script_tag( name: "impact", value: "Attackers can exploit these issues to obtain potentially sensitive
  information that may lead to further attacks." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version/build is present on the target host." );
	script_tag( name: "insight", value: "The AdminUI in Trend Micro InterScan Web Security Virtual Appliance (IWSVA)
  allows remote authenticated users to read arbitrary files via vectors related to configuration input when saving filters." );
	script_tag( name: "solution", value: "Update to 6.0 HF build 1244 or later." );
	script_tag( name: "summary", value: "Trend Micro InterScan Web Security Virtual Appliance is prone to
  multiple information-disclosure vulnerabilities." );
	script_tag( name: "affected", value: "Trend Micro InterScan Web Security Virtual Appliance (IWSVA) before 6.0 HF build 1244." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "2020-07-07 12:31:23 +0000 (Tue, 07 Jul 2020)" );
	script_tag( name: "creation_date", value: "2015-04-08 10:22:02 +0200 (Wed, 08 Apr 2015)" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_trend_micro_interscan_web_security_virtual_appliance_consolidation.sc" );
	script_mandatory_keys( "trendmicro/IWSVA/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(!build = get_kb_item( "trendmicro/IWSVA/build" )){
	build = 0;
}
if(version_is_less( version: vers, test_version: "6.0" )){
	vuln = TRUE;
}
if(vers == "6.0" && int( build ) < 1244){
	vuln = TRUE;
}
if(vuln){
	report = report_fixed_ver( installed_version: vers, installed_build: build, fixed_version: "6.0", fixed_build: "1244" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

