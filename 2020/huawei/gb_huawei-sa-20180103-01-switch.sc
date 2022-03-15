if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107843" );
	script_version( "2020-10-22T07:29:51+0000" );
	script_tag( name: "last_modification", value: "2020-10-22 07:29:51 +0000 (Thu, 22 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-06-25 22:42:17 +0200 (Thu, 25 Jun 2020)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Huawei Data Communication: DoS Vulnerability in Some Huawei Switch Products (huawei-sa-20180103-01-switch)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei" );
	script_dependencies( "gb_huawei_vrp_network_device_consolidation.sc" );
	script_mandatory_keys( "huawei/vrp/detected" );
	script_tag( name: "summary", value: "There is a denial of service (DoS) vulnerability in Some Huawei switch products." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An unauthenticated, remote attacker is able to craft oversized packets and to send these
  packets to the affected products. Due to insufficient verification of the packets, successful exploitation may cause
  service unavailability and a denial of service (DoS) condition. (Vulnerability ID: HWPSIRT-2017-10069)" );
	script_tag( name: "impact", value: "By exploiting this vulnerability, the attacker can cause the service unavailability and denial of service (DoS) condition." );
	script_tag( name: "affected", value: "S7700 versions V100R006C00 V200R001C00 V200R002C00

  S9700 versions V200R001C00" );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_xref( name: "URL", value: "https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20180103-01-switch-en" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/o:huawei:s7700_firmware",
	 "cpe:/o:huawei:s9700_firmware" );
if(!infos = get_app_version_from_list( cpe_list: cpe_list, nofork: TRUE )){
	exit( 0 );
}
cpe = infos["cpe"];
version = toupper( infos["version"] );
patch = get_kb_item( "huawei/vrp/patch" );
if( cpe == "cpe:/o:huawei:s7700_firmware" ){
	if(IsMatchRegexp( version, "^V100R006C00" ) || IsMatchRegexp( version, "^V200R001C00" ) || IsMatchRegexp( version, "^V200R002C00" )){
		if(!patch || version_is_less( version: patch, test_version: "V2R10C00" )){
			report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V2R10C00" );
			security_message( port: 0, data: report );
			exit( 0 );
		}
	}
}
else {
	if(cpe == "cpe:/o:huawei:s9700_firmware"){
		if(IsMatchRegexp( version, "^V200R001C00" )){
			if(!patch || version_is_less( version: patch, test_version: "V2R10C00" )){
				report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V2R10C00" );
				security_message( port: 0, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

