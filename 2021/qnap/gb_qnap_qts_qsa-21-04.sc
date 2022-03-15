CPE_PREFIX = "cpe:/h:qnap";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145778" );
	script_version( "2021-08-17T09:01:01+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 09:01:01 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-04-19 04:37:10 +0000 (Mon, 19 Apr 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-21 16:57:00 +0000 (Mon, 21 Jun 2021)" );
	script_cve_id( "CVE-2018-19942" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "QNAP QTS XSS Vulnerability (QSA-21-04)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_qnap_nas_detect.sc" );
	script_mandatory_keys( "qnap/qts" );
	script_tag( name: "summary", value: "QNAP QTS is prone to a cross-site scripting (XSS) vulnerability in
  File Station." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An XSS vulnerability has been reported to affect earlier versions of File
  Station. If exploited, this vulnerability allows remote attackers to inject malicious code." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_xref( name: "URL", value: "https://www.qnap.com/zh-tw/security-advisory/qsa-21-04" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_port_from_cpe_prefix( cpe: CPE_PREFIX )){
	exit( 0 );
}
CPE = infos["cpe"];
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "4.2.6_20210327" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.2.6_20210327" );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.3", test_version2: "4.3.3_20201005" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.3.3_20201006" );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.3.4", test_version2: "4.3.4_20201005" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.3.4_20201006" );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.3.5", test_version2: "4.3.6_20200928" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.3.6_20200929" );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.5", test_version2: "4.5.1_20201014" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.5.1_20201015" );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.5.2", test_version2: "4.5.2_20210201" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.5.2_20210202" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

