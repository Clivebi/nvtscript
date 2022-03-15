CPE = "cpe:/a:cesanta:mongoose";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143214" );
	script_version( "2021-09-08T08:01:40+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 08:01:40 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-12-03 02:22:54 +0000 (Tue, 03 Dec 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_cve_id( "CVE-2019-19307" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Mongoose Web Server < 6.17 DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_mongoose_web_server_http_detect.sc" );
	script_mandatory_keys( "cesanta/mongoose/detected" );
	script_tag( name: "summary", value: "Mongoose Web Server is prone to a denial of service (DoS)
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An integer overflow in parse_mqtt in mongoose.c in Cesanta
  Mongoose Web Server allows an attacker to achieve remote DoS (infinite loop), or possibly cause an
  out-of-bounds write, by sending a crafted MQTT protocol packet." );
	script_tag( name: "affected", value: "Mongoose Web Server version 6.16 and probably prior." );
	script_tag( name: "solution", value: "Update to version 6.17 or later." );
	script_xref( name: "URL", value: "https://github.com/cesanta/mongoose/issues/1055" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "6.17" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.17", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

