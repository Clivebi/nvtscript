CPE = "cpe:/a:apache:traffic_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145184" );
	script_version( "2021-08-24T09:01:06+0000" );
	script_tag( name: "last_modification", value: "2021-08-24 09:01:06 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-01-18 06:39:42 +0000 (Mon, 18 Jan 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-14 20:20:00 +0000 (Thu, 14 Jan 2021)" );
	script_cve_id( "CVE-2020-17508" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Apache Traffic Server (ATS) < 7.1.12, 8.x < 8.1.1 Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_traffic_detect.sc" );
	script_mandatory_keys( "apache_trafficserver/installed" );
	script_tag( name: "summary", value: "Apache Traffic Server is prone to an information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The ATS ESI plugin has a memory disclosure vulnerability." );
	script_tag( name: "affected", value: "Apache Traffic Server versions 6.0.0 - 6.2.3, 7.0.0 - 7.1.11 and 8.0.0 - 8.1.0." );
	script_tag( name: "solution", value: "Update to version 7.1.12, 8.1.1 or later." );
	script_xref( name: "URL", value: "https://lists.apache.org/thread.html/r65434f7acca3aebf81b0588587149c893fe9f8f9f159eaa7364a70ff%40%3Cannounce.trafficserver.apache.org%3E" );
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
if(version_in_range( version: version, test_version: "6.0.0", test_version2: "6.2.3" ) || version_in_range( version: version, test_version: "7.0.0", test_version2: "7.1.11" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.1.12" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "8.0.0", test_version2: "8.1.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.1.1" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

