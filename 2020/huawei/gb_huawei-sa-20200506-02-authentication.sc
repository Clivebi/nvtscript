if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144095" );
	script_version( "2021-08-17T12:00:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 12:00:57 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-06-09 08:02:53 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-11 18:42:00 +0000 (Thu, 11 Jun 2020)" );
	script_cve_id( "CVE-2020-9099" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Huawei Products Improper Authentication Vulnerability (huawei-sa-20200506-02-authentication)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei" );
	script_dependencies( "gb_huawei_vrp_network_device_consolidation.sc" );
	script_mandatory_keys( "huawei/vrp/detected" );
	script_tag( name: "summary", value: "Multiple Huawei products are prone to an improper authentication vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Attackers need to perform some operations to exploit the vulnerability.
  Successful exploit may obtain certain permissions on the device." );
	script_tag( name: "impact", value: "Attackers can exploit this vulnerability to obtain certain device permissions." );
	script_tag( name: "affected", value: "Huawei IPS Module, NGFW Module, NIP6300, NIP6600, NIP6800,
  Secospace USG6300, Secospace USG6500, Secospace USG6600 and USG9500." );
	script_tag( name: "solution", value: "See the referenced vendor advisory for a solution." );
	script_xref( name: "URL", value: "http://www.huawei.com/en/psirt/security-advisories/huawei-sa-20200506-02-authentication" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/o:huawei:usg6300_firmware",
	 "cpe:/o:huawei:usg6500_firmware",
	 "cpe:/o:huawei:usg6600_firmware",
	 "cpe:/o:huawei:usg9500_firmware" );
if(!infos = get_app_version_from_list( cpe_list: cpe_list, nofork: TRUE )){
	exit( 0 );
}
cpe = infos["cpe"];
version = toupper( infos["version"] );
patch = get_kb_item( "huawei/vrp/patch" );
if(version == "V500R001C00" || version == "V500R001C20" || version == "V500R001C30" || version == "V500R001C50" || version == "V500R001C60" || version == "V500R001C80" || version == "V500R005C00" || version == "V500R005C10" || version == "V500R005C20"){
	report = report_fixed_ver( installed_version: version, installed_patch: patch, fixed_version: "V500R005C20SPC500", fixed_patch: "V500R005SPH007" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

