if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813521" );
	script_version( "2021-05-27T06:00:15+0200" );
	script_cve_id( "CVE-2017-13072" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-05-27 06:00:15 +0200 (Thu, 27 May 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-10 14:11:00 +0000 (Fri, 10 Aug 2018)" );
	script_tag( name: "creation_date", value: "2018-06-12 11:14:29 +0530 (Tue, 12 Jun 2018)" );
	script_name( "QNAP QTS App Center XSS Vulnerability" );
	script_tag( name: "summary", value: "This host is running QNAP QTS and is prone
  to XSS vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to insufficient
  sanitization of user-supplied data in App Center." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to inject Javascript code in the compromised application." );
	script_tag( name: "affected", value: "QNAP QTS versions 4.2.6 build 20171208 and
  earlier, 4.3.3 build 20171213 and earlier, 4.3.4 build 20171223 and earlier." );
	script_tag( name: "solution", value: "Upgrade to QNAP QTS 4.2.6 build 20180504,
  4.3.3 build 20180126 or 4.3.4 build 20171230 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://www.qnap.com/en-in/security-advisory/nas-201805-16" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_dependencies( "gb_qnap_nas_detect.sc" );
	script_mandatory_keys( "qnap/qts", "qnap/version", "qnap/build", "qnap/port" );
	script_require_ports( "Services/www", 80, 8080 );
	exit( 0 );
}
require("version_func.inc.sc");
if(!version = get_kb_item( "qnap/version" )){
	exit( 0 );
}
if(!build = get_kb_item( "qnap/build" )){
	exit( 0 );
}
if(!port = get_kb_item( "qnap/port" )){
	exit( 0 );
}
cv = version + "." + build;
if( IsMatchRegexp( cv, "^4\\.2\\.6" ) && version_is_less( version: cv, test_version: "4.2.6.20180504" ) ){
	fix = "4.2.6";
	fix_build = "20180504";
}
else {
	if( IsMatchRegexp( cv, "^4\\.3\\.3" ) && version_is_less( version: cv, test_version: "4.3.3.20180126" ) ){
		fix = "4.3.3.0448";
		fix_build = "20180126";
	}
	else {
		if(IsMatchRegexp( cv, "^4\\.3\\.4" ) && version_is_less( version: cv, test_version: "4.3.4.20171230" )){
			fix = "4.3.4.0435";
			fix_build = "20171230";
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: version, installed_build: build, fixed_version: fix, fixed_build: fix_build );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

