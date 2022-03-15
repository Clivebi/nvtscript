CPE_PREFIX = "cpe:/h:qnap";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106880" );
	script_version( "2021-09-09T08:01:35+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 08:01:35 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-06-16 16:07:13 +0700 (Fri, 16 Jun 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-06-22 12:37:00 +0000 (Thu, 22 Jun 2017)" );
	script_cve_id( "CVE-2017-7629" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "QNAP QTS Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_qnap_nas_detect.sc" );
	script_mandatory_keys( "qnap/qts", "qnap/version", "qnap/build" );
	script_tag( name: "summary", value: "QNAP QTS is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "QNAP QTS before QTS 4.2.6 build 20170607 and before QTS 4.3.3.0210 Build
  20170606" );
	script_tag( name: "solution", value: "Update to QTS 4.2.6 build 20170607, QTS 4.3.3.0210 Build 20170606 or
  later." );
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
if(version_is_less( version: checkvers, test_version: "4.2.6.20170607" )){
	report = report_fixed_ver( installed_version: version, installed_build: build, fixed_version: "4.2.6", fixed_build: "20170607" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(IsMatchRegexp( version, "^4\\.3\\." )){
	if(version_is_less( version: checkvers, test_version: "4.3.3.20170606" )){
		report = report_fixed_ver( installed_version: version, installed_build: build, fixed_version: "4.3.3", fixed_build: "20170606" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

