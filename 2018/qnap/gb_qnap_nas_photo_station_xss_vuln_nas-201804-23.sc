CPE = "cpe:/o:qnap:qts_photo_station";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813165" );
	script_version( "2021-05-27T06:00:15+0200" );
	script_cve_id( "CVE-2017-13073" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-05-27 06:00:15 +0200 (Thu, 27 May 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-05-25 14:23:00 +0000 (Fri, 25 May 2018)" );
	script_tag( name: "creation_date", value: "2018-05-07 10:36:25 +0530 (Mon, 07 May 2018)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "QNAP NAS Photo Station XSS Vulnerability (nas-201804-23)" );
	script_tag( name: "summary", value: "QNAP NAS Photo Station is prone to a cross-site
  scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on
  the target host." );
	script_tag( name: "insight", value: "The flaw exists due to insufficient sanitization
  of user supplied input." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML code." );
	script_tag( name: "affected", value: "QNAP Photo Station versions 5.4.3 and earlier
  for QTS 4.3.x, Photo Station versions 5.2.7 and earlier for QTS 4.2.x" );
	script_tag( name: "solution", value: "Update QNAP Photo Station to version 5.4.4
  or later for QTS 4.3.x, and to version 5.2.8 or later for QTS 4.2.x." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.qnap.com/en/security-advisory/nas-201804-23" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_qnap_nas_photo_station_detect.sc" );
	script_mandatory_keys( "QNAP/QTS/PS/baseQTSVer", "QNAP/QTS/PhotoStation/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
vers = get_kb_item( "QNAP/QTS/PS/baseQTSVer" );
if( IsMatchRegexp( vers, "^4\\.3\\." ) ){
	if(version_is_less( version: version, test_version: "5.4.4" )){
		fix = "5.4.4";
	}
}
else {
	if(IsMatchRegexp( vers, "^4\\.2\\." )){
		if(version_is_less( version: version, test_version: "5.2.8" )){
			fix = "5.2.8";
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: version, fixed_version: fix );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

