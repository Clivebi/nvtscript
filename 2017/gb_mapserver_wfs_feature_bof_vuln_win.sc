CPE = "cpe:/a:umn:mapserver";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810790" );
	script_version( "2021-09-30T08:43:52+0000" );
	script_cve_id( "CVE-2017-5522" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-30 08:43:52 +0000 (Thu, 30 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-07 15:56:00 +0000 (Mon, 07 Jun 2021)" );
	script_tag( name: "creation_date", value: "2017-06-06 11:47:44 +0530 (Tue, 06 Jun 2017)" );
	script_name( "MapServer WFS Feature Requests Buffer Overflow Vulnerability (Windows)" );
	script_tag( name: "summary", value: "MapServer is prone to a buffer overflow vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an error in 'WFS' get
  feature requests. Does not handle with specific WFS get feature requests
  properly." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to crash the service, or potentially execute arbitrary code." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "affected", value: "MapServer versions before 6.0.6,
  6.2.x before 6.2.4, 6.4.x before 6.4.5, and 7.0.x before 7.0.4 on Windows." );
	script_tag( name: "solution", value: "Upgrade to version 6.0.6, 6.2.4, 6.4.5,
  7.0.4 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://lists.osgeo.org/pipermail/mapserver-dev/2017-January/015007.html" );
	script_xref( name: "URL", value: "http://www.mapserver.org/development/changelog/changelog-6-4.html#changelog-6-4-5" );
	script_xref( name: "URL", value: "http://www.mapserver.org/development/changelog/changelog-7-0.html#changelog-7-0-4" );
	script_xref( name: "URL", value: "https://github.com/mapserver/mapserver/commit/e52a436c0e1c5e9f7ef13428dba83194a800f4df" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web Servers" );
	script_dependencies( "os_detection.sc", "gb_mapserver_detect.sc" );
	script_mandatory_keys( "MapServer/Installed", "Host/runs_windows" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!webPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!webVer = get_app_version( cpe: CPE, port: webPort )){
	exit( 0 );
}
if( version_is_less( version: webVer, test_version: "6.0.6" ) ){
	fix = "6.0.6";
}
else {
	if( ( IsMatchRegexp( webVer, "^6\\.2\\." ) ) && version_is_less( version: webVer, test_version: "6.2.4" ) ){
		fix = "6.2.4";
	}
	else {
		if( ( IsMatchRegexp( webVer, "^6\\.4\\." ) ) && version_is_less( version: webVer, test_version: "6.4.5" ) ){
			fix = "6.4.5";
		}
		else {
			if(( IsMatchRegexp( webVer, "^7\\.0\\." ) ) && version_is_less( version: webVer, test_version: "7.0.4" )){
				fix = "7.0.4";
			}
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: webVer, fixed_version: fix );
	security_message( data: report, port: webPort );
	exit( 0 );
}

