if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112483" );
	script_version( "2021-09-08T09:01:34+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 09:01:34 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-01-14 11:06:12 +0100 (Mon, 14 Jan 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-01-30 20:19:00 +0000 (Wed, 30 Jan 2019)" );
	script_cve_id( "CVE-2019-5748" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Traccar Server <= 4.2 XXE Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_traccar_detect.sc" );
	script_mandatory_keys( "traccar/detected" );
	script_tag( name: "summary", value: "Traccar is prone to an XXE vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerable vector to allow such an attack lies in protocol/SpotProtocolDecoder.java." );
	script_tag( name: "affected", value: "Traccar Server through version 4.2." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_xref( name: "URL", value: "https://github.com/traccar/traccar/commit/d7f6c53fd88635885914013649b6807ec53227bf" );
	script_xref( name: "URL", value: "https://www.traccar.org/blog/" );
	exit( 0 );
}
CPE = "cpe:/a:traccar:traccar";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "4.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See references" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

