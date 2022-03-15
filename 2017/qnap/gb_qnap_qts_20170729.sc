CPE_PREFIX = "cpe:/h:qnap";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140260" );
	script_version( "2021-09-09T08:01:35+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 08:01:35 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-01 10:17:13 +0700 (Tue, 01 Aug 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-11 15:15:00 +0000 (Fri, 11 Sep 2020)" );
	script_cve_id( "CVE-2017-7876", "CVE-2017-11103", "CVE-2017-1000364" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "QNAP QTS Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_qnap_nas_detect.sc" );
	script_mandatory_keys( "qnap/qts", "qnap/version", "qnap/build" );
	script_tag( name: "summary", value: "QNAP QTS is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "QNAP QTS is prone to multiple vulnerabilities:

  - Multiple vulnerabilities regarding OpenVPN.

  - Multiple OS command injection vulnerabilities. (CVE-2017-7876)

  - Vulnerability in ActiveX controls that could allow for arbitrary code execution on the web client.

  - XSS vulnerability in Storage Manager and Backup Station.

  - 'Orpheus' Lyre' vulnerability in Samba that could be exploited to bypass authentication mechanisms. (CVE-2017-11103)

  - Vulnerability in the Linux kernel that could be exploited to circumvent the stack guard page. (CVE-2017-1000364)" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "QNAP QTS before QTS 4.2.6 build 20170729 and before QTS 4.3.3.0262 build 20170727" );
	script_tag( name: "solution", value: "Update to QTS 4.2.6 build 20170729, QTS 4.3.3.0262 build 20170727 or later." );
	script_xref( name: "URL", value: "https://www.qnap.com/en-us/releasenotes/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_port_from_cpe_prefix( cpe: CPE_PREFIX )){
	exit( 0 );
}
port = infos["port"];
CPE = infos["cpe"];
if(!version = get_kb_item( "qnap/version" )){
	exit( 0 );
}
if(!build = get_kb_item( "qnap/build" )){
	exit( 0 );
}
checkvers = version + "." + build;
if(version_is_less( version: checkvers, test_version: "4.2.6.20170729" )){
	report = report_fixed_ver( installed_version: version, installed_build: build, fixed_version: "4.2.6", fixed_build: "20170729" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(IsMatchRegexp( version, "^4\\.3\\." )){
	if(version_is_less( version: checkvers, test_version: "4.3.3.20170727" )){
		report = report_fixed_ver( installed_version: version, installed_build: build, fixed_version: "4.3.3", fixed_build: "20170727" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

