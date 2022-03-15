CPE = "cpe:/o:axis:m1033-w_firmware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113151" );
	script_version( "2021-05-31T06:00:14+0200" );
	script_tag( name: "last_modification", value: "2021-05-31 06:00:14 +0200 (Mon, 31 May 2021)" );
	script_tag( name: "creation_date", value: "2018-04-06 13:37:37 +0200 (Fri, 06 Apr 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-05-15 15:35:00 +0000 (Tue, 15 May 2018)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2018-9158" );
	script_name( "AXIS M1033-W IP Camera Denial of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_axis_network_cameras_ftp_detect.sc" );
	script_mandatory_keys( "axis/camera/detected" );
	script_tag( name: "summary", value: "An issue was discovered on AXIS M1033-W (IP camera) devices.
  They don't employ a suitable mechanism to prevent a DoS attack, which leads to a response time delay." );
	script_tag( name: "impact", value: "An attacker can use the hping3 tool to perform an IPv4 flood attack,
  and the services are interrupted from attack start to end." );
	script_tag( name: "vuldetect", value: "The script checks if the target is a vulnerable device running a vulnerable firmware version." );
	script_tag( name: "affected", value: "Firmware before version 5.50.5.0" );
	script_tag( name: "solution", value: "Update to firmware version 5.50.5.0 or above." );
	script_xref( name: "URL", value: "https://www.slideshare.net/secret/HpAEwK5qo5U4b1" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "5.50.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.50.5" );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

