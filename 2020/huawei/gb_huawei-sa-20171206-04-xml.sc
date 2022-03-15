if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143985" );
	script_version( "2021-08-17T12:00:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 12:00:57 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-05-27 04:40:46 +0000 (Wed, 27 May 2020)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_cve_id( "CVE-2017-17330" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Huawei Products Memory Leak Vulnerability (huawei-sa-20171206-04-xml)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei" );
	script_dependencies( "gb_huawei_vrp_network_device_consolidation.sc" );
	script_mandatory_keys( "huawei/vrp/detected" );
	script_tag( name: "summary", value: "Multiple Huawei products are prone a memory leak vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The software does not release allocated memory properly when parse XML
  element data. An authenticated attacker could upload a crafted XML file, successful exploit could cause the
  system service abnormal since run out of memory." );
	script_tag( name: "impact", value: "Successful exploit could cause the system service abnormal since run out of
  memory." );
	script_tag( name: "affected", value: "Huawei AR3200 and NGFW Module." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_xref( name: "URL", value: "http://www.huawei.com/en/psirt/security-advisories/huawei-sa-20171206-04-xml-en" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/o:huawei:ar3200_firmware" );
if(!infos = get_app_version_from_list( cpe_list: cpe_list, nofork: TRUE )){
	exit( 0 );
}
cpe = infos["cpe"];
version = toupper( infos["version"] );
if(cpe == "cpe:/o:huawei:ar3200_firmware"){
	if(version == "V200R005C32" || version == "V200R006C10" || version == "V200R006C11" || version == "V200R007C00" || version == "V200R007C01" || version == "V200R007C02" || version == "V200R008C00" || version == "V200R008C10" || version == "V200R008C20" || version == "V200R008C30"){
		report = report_fixed_ver( installed_version: version, fixed_version: "V200R009C00" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

