CPE_PREFIX = "cpe:/h:qnap";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107275" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2021-09-09T08:01:35+0000" );
	script_name( "QNAP QTS Command Injection Vulnerability" );
	script_xref( name: "URL", value: "https://www.lateralsecurity.com/downloads/Lateral_Security-Advisory-QNAP_QTS_CVE-2017-10700.pdf" );
	script_xref( name: "URL", value: "https://www.qnap.com/de-de/security-advisory/nas-201709-11" );
	script_cve_id( "CVE-2017-10700" );
	script_tag( name: "last_modification", value: "2021-09-09 08:01:35 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-12-13 13:24:30 +0100 (Wed, 13 Dec 2017)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_qnap_nas_detect.sc" );
	script_require_ports( "Services/www", 80, 8080 );
	script_mandatory_keys( "qnap/qts", "qnap/version", "qnap/build" );
	script_tag( name: "vuldetect", value: "Check the firmware version" );
	script_tag( name: "solution", value: "Update QTS 4.2.6 build 20170905 or QTS 4.3.3.0262 build 20170727." );
	script_tag( name: "summary", value: "QNAP QTS is vulnerable to command injection vulnerability." );
	script_tag( name: "insight", value: "The media library service fails to sufficiently sanitise user inputs." );
	script_tag( name: "impact", value: "A remote, un-authenticated attacker can provide inputs to this service
  which executes system commands in the context of the 'admin' user of the QNAP device." );
	script_tag( name: "affected", value: "QNAP QTS versions 4.3.x before 4.3.3.0262 build 20170727 and
  4.2.x before QTS 4.2.6 build 20170905." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
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
V = version + "." + build;
if( IsMatchRegexp( version, "^4\\.3\\." ) ){
	if(version_is_less( version: V, test_version: "4.3.3.20170727" )){
		report = report_fixed_ver( installed_version: version, installed_build: build, fixed_version: "4.3.3", fixed_build: "20170727" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
else {
	if(IsMatchRegexp( version, "^4\\.2\\." )){
		if(version_is_less( version: V, test_version: "4.2.6.20170905" )){
			report = report_fixed_ver( installed_version: version, installed_build: build, fixed_version: "4.2.6", fixed_build: "20170905" );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

