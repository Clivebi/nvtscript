CPE = "cpe:/a:nuuo:nuuo";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141484" );
	script_version( "2021-05-28T07:06:21+0000" );
	script_tag( name: "last_modification", value: "2021-05-28 07:06:21 +0000 (Fri, 28 May 2021)" );
	script_tag( name: "creation_date", value: "2018-09-18 08:45:02 +0700 (Tue, 18 Sep 2018)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-12-07 19:36:00 +0000 (Fri, 07 Dec 2018)" );
	script_cve_id( "CVE-2018-1149", "CVE-2018-1150" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "NUUO NVR < 3.9.1 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_nuuo_devices_web_detect.sc" );
	script_mandatory_keys( "nuuo/web/detected" );
	script_tag( name: "summary", value: "NUUO Network Video Recorder (NVR) is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "NUUO Network Video Recorder (NVR) is prone to multiple vulnerabilities:

  - Unauthenticated Stack Buffer Overflow (CVE-2018-1149) dubbed 'Peekaboo'

  - Backdoor functionality (CVE-2018-1150)" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to version 3.9.1 (03.09.0001.0000) or later." );
	script_xref( name: "URL", value: "https://www.nuuo.com/NewsDetail.php?id=0425" );
	script_xref( name: "URL", value: "https://github.com/tenable/poc/tree/master/nuuo/nvrmini2" );
	script_xref( name: "URL", value: "https://www.tenable.com/blog/tenable-research-advisory-peekaboo-critical-vulnerability-in-nuuo-network-video-recorder" );
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
if(version_is_less( version: version, test_version: "3.9.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.9.1" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

