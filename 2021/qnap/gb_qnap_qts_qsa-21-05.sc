CPE_PREFIX = "cpe:/h:qnap";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145776" );
	script_version( "2021-08-17T09:01:01+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 09:01:01 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-04-19 04:03:36 +0000 (Mon, 19 Apr 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-21 16:56:00 +0000 (Mon, 21 Jun 2021)" );
	script_cve_id( "CVE-2020-2509" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "QNAP QTS Command Injection Vulnerability (QSA-21-05)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_qnap_nas_detect.sc" );
	script_mandatory_keys( "qnap/qts" );
	script_tag( name: "summary", value: "QNAP QTS is prone to a command injection vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A command injection vulnerability has been reported to affect QTS. If
  exploited, this vulnerability allows attackers to execute arbitrary commands in a compromised application." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_xref( name: "URL", value: "https://www.qnap.com/en/security-advisory/qsa-21-05" );
	script_xref( name: "URL", value: "https://securingsam.com/new-vulnerabilities-allow-complete-takeover/" );
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
if(version_in_range( version: version, test_version: "4.3", test_version2: "4.3.3_20210415" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.3.3_20210416" );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.3.4", test_version2: "4.3.4_20210323" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.3.4_20210324" );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.3.5", test_version2: "4.3.6_20210321" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.3.6_20210322" );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.5", test_version2: "4.5.1_20201122" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.5.1_20201123" );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.5.2", test_version2: "4.5.2_20210201" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.5.2_20210202" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

