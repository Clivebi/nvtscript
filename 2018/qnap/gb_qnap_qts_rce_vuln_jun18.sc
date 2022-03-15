if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113216" );
	script_version( "2021-05-27T06:00:15+0200" );
	script_tag( name: "last_modification", value: "2021-05-27 06:00:15 +0200 (Thu, 27 May 2021)" );
	script_tag( name: "creation_date", value: "2018-06-26 15:13:57 +0200 (Tue, 26 Jun 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2018-0712" );
	script_name( "QNAP QTS <= 4.2.6, <= 4.3.3, 4.3.4 RCE Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_qnap_nas_detect.sc" );
	script_mandatory_keys( "qnap/qts" );
	script_tag( name: "summary", value: "QNAP QTS is prone to a Remote Code Execution (RCE)
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on
  the target host." );
	script_tag( name: "insight", value: "The flaw exists within the LDAP Server of QNAP QTS." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to gain
  complete control over the target system." );
	script_tag( name: "affected", value: "QNAP QTS through version 4.2.6 build 20171208, 4.3.x
  through version 4.3.3 build 20180402 and 4.3.4 through build 20180413." );
	script_tag( name: "solution", value: "Update to version 4.2.6 build 20180504, 4.3.3 build
  20180504 or 4.3.4 build 20180501 respectively." );
	script_xref( name: "URL", value: "https://www.qnap.com/en/security-advisory/nas-201806-19" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!model = get_kb_item( "qnap/model" )){
	exit( 0 );
}
CPE = "cpe:/h:qnap:" + tolower( model );
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "4.2.6_20180504" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.2.6 build 20180504" );
	security_message( data: report, port: 0 );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.3.0_00000000", test_version2: "4.3.3_20180402" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.3.3 build 20180504" );
	security_message( data: report, port: 0 );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.3.4_00000000", test_version2: "4.3.4_20180413" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.3.4 build 20180501" );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

