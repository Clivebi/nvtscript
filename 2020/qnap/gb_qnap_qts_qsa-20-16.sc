CPE_PREFIX = "cpe:/h:qnap";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145024" );
	script_version( "2021-07-06T11:00:47+0000" );
	script_tag( name: "last_modification", value: "2021-07-06 11:00:47 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-12-11 04:16:21 +0000 (Fri, 11 Dec 2020)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-21 16:57:00 +0000 (Mon, 21 Jun 2021)" );
	script_cve_id( "CVE-2019-7198" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "QNAP QTS Command Injection Vulnerability (QSA-20-16)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_qnap_nas_detect.sc" );
	script_mandatory_keys( "qnap/qts" );
	script_tag( name: "summary", value: "QNAP QTS is prone to a command injection vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "This command injection vulnerability allows attackers to execute arbitrary
  commands in a compromised application." );
	script_tag( name: "affected", value: "QNAP QTS prior to versions 4.4.3.1354 build 20200702 and 4.5.1.1456 build 20201015." );
	script_tag( name: "solution", value: "Update to version 4.4.3.1354 build 20200702, 4.5.1.1456 build 20201015 or later." );
	script_xref( name: "URL", value: "https://www.qnap.com/en/security-advisory/qsa-20-16" );
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
if(version_is_less( version: version, test_version: "4.4.3_20200702" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.4.3_20200702" );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(IsMatchRegexp( version, "^4\\.5" ) && version_is_less( version: version, test_version: "4.5.1_20201015" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.5.1_20201015" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

