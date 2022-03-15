CPE = "cpe:/a:h2o_project:h2o";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141139" );
	script_version( "2021-05-27T09:28:58+0000" );
	script_tag( name: "last_modification", value: "2021-05-27 09:28:58 +0000 (Thu, 27 May 2021)" );
	script_tag( name: "creation_date", value: "2018-06-05 11:05:59 +0700 (Tue, 05 Jun 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-19 14:01:00 +0000 (Mon, 19 Apr 2021)" );
	script_cve_id( "CVE-2018-0608" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "H2O HTTP Server < 2.2.5 Heap Overflow Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_h2o_http_server_detect.sc" );
	script_mandatory_keys( "h2o/installed" );
	script_tag( name: "summary", value: "H2O HTTP Server is prone to a heap buffer overflow while trying to emit
access log." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "H2O version 2.2.4 and prior." );
	script_tag( name: "solution", value: "Update to version 2.2.5 or later." );
	script_xref( name: "URL", value: "https://github.com/h2o/h2o/issues/1775" );
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
if(version_is_less( version: version, test_version: "2.2.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.2.5" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

