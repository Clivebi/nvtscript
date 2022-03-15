CPE = "cpe:/a:nuuo:nuuo";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141762" );
	script_version( "2021-05-28T07:06:21+0000" );
	script_tag( name: "last_modification", value: "2021-05-28 07:06:21 +0000 (Fri, 28 May 2021)" );
	script_tag( name: "creation_date", value: "2018-12-06 11:32:59 +0700 (Thu, 06 Dec 2018)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-04 23:29:00 +0000 (Tue, 04 Jun 2019)" );
	script_cve_id( "CVE-2018-19864" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "NUUO NVRmini2 < 3.10.0 Remote Stack Overflow Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_nuuo_devices_web_detect.sc" );
	script_mandatory_keys( "nuuo/web/detected" );
	script_tag( name: "summary", value: "NUUO NVRmini2 is prone to a unauthenticated remote stack overflow
vulnerability." );
	script_tag( name: "insight", value: "Sending a crafted GET request to the affected service with a URI length of 351
or greater will trigger the stack overflow. Overflowing of the stack variable, which is intended to hold the
request data, results in the overwriting of stored return addresses, and with a properly crafted payload, can be
leveraged to achieve arbitrary code execution." );
	script_tag( name: "impact", value: "Remote, unauthenticated users can execute arbitrary code on the affected system
with root privileges." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to version 3.10.0 or later." );
	script_xref( name: "URL", value: "https://www.digitaldefense.com/blog/zero-day-alerts/nuuo-firmware-disclosure/" );
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
if(version_is_less( version: version, test_version: "3.10.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.10.0" );
	security_message( port: port, data: report );
	exit( 0 );
}

