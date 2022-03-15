if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140219" );
	script_cve_id( "CVE-2017-6361", "CVE-2017-6360", "CVE-2017-6359" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-09 08:01:35 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-03-24 12:56:10 +0100 (Fri, 24 Mar 2017)" );
	script_version( "2021-09-09T08:01:35+0000" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_name( "QNAP QTS Multiple Arbitrary Command Execution Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_qnap_nas_detect.sc" );
	script_require_ports( "Services/www", 80, 8080 );
	script_mandatory_keys( "qnap/qts", "qnap/version", "qnap/build" );
	script_xref( name: "URL", value: "https://www.qnap.com/en-us/releasenotes/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/97059" );
	script_tag( name: "vuldetect", value: "Check the firmware version" );
	script_tag( name: "solution", value: "Update to QNAP QTS  4.2.4 Build 20170313 or newer." );
	script_tag( name: "summary", value: "QNAP QTS is prone to multiple arbitrary command-execution vulnerabilities." );
	script_tag( name: "affected", value: "QNAP QTS <  4.2.4 Build 20170313, all models." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
if(!version = get_kb_item( "qnap/version" )){
	exit( 0 );
}
if(!build = get_kb_item( "qnap/build" )){
	exit( 0 );
}
cv = version + "." + build;
if(version_is_less( version: cv, test_version: "4.2.4.20170313" )){
	report = report_fixed_ver( installed_version: version, installed_build: build, fixed_version: "4.2.4", fixed_build: "20170313" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

