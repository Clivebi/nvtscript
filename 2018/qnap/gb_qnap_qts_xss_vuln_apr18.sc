if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813120" );
	script_version( "2021-05-27T06:00:15+0200" );
	script_cve_id( "CVE-2017-7632" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-05-27 06:00:15 +0200 (Thu, 27 May 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-04-18 16:05:00 +0000 (Wed, 18 Apr 2018)" );
	script_tag( name: "creation_date", value: "2018-04-20 10:36:37 +0530 (Fri, 20 Apr 2018)" );
	script_name( "QNAP QTS Cross-Site Scripting Vulnerability-Apr18" );
	script_tag( name: "summary", value: "This host is running QNAP QTS and is prone
  to cross site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists as application does not
  properly filter HTML code from user-supplied input before displaying the input." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct cross-site scripting attacks." );
	script_tag( name: "affected", value: "QNAP QTS versions 4.2.6 build 20171026 and
  prior, 4.3.3 build 20170727 and prior." );
	script_tag( name: "solution", value: "Upgrade to QNAP QTS 4.2.6 build 20171028
  or 4.3.3 Build 20170901 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://www.qnap.com/nl-nl/security-advisory/nas-201803-23" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_dependencies( "gb_qnap_nas_detect.sc" );
	script_mandatory_keys( "qnap/qts", "qnap/version", "qnap/build" );
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
cv = version + "." + build;
if( version_is_less_equal( version: cv, test_version: "4.2.6.20171026" ) ){
	fix = "4.2.6";
	fix_build = "20171208";
}
else {
	if(IsMatchRegexp( cv, "^(4\\.3\\.)" ) && version_is_less_equal( version: cv, test_version: "4.3.3.20170727" )){
		fix = "4.3.3";
		fix_build = "20170901";
	}
}
if(fix){
	report = report_fixed_ver( installed_version: version, installed_build: build, fixed_version: fix, fixed_build: fix_build );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 0 );

