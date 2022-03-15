if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117176" );
	script_version( "2021-01-22T13:09:04+0000" );
	script_tag( name: "last_modification", value: "2021-01-22 13:09:04 +0000 (Fri, 22 Jan 2021)" );
	script_tag( name: "creation_date", value: "2021-01-22 13:01:51 +0000 (Fri, 22 Jan 2021)" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Western Digital My Cloud Multiple Products 5.0 < 5.09.115 Buffer Overflow Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wd_mycloud_consolidation.sc" );
	script_mandatory_keys( "wd-mycloud/detected" );
	script_tag( name: "summary", value: "Multiple Western Digital My Cloud products are prone to a buffer
  overflow vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "There was a buffer overflow issue on Smart.cgi." );
	script_tag( name: "affected", value: "Western Digital My Cloud PR2100, My Cloud PR4100, My Cloud EX2 Ultra, My Cloud EX2100,
  My Cloud EX4100, My Cloud Mirror Gen 2, My Cloud DL2100, My Cloud DL4100 and My Cloud (P/N: WDBCTLxxxxxx-10) with firmware
  versions prior to 5.09.115." );
	script_tag( name: "solution", value: "Update to firmware version 5.09.115 or later." );
	script_xref( name: "URL", value: "https://community.wd.com/t/my-cloud-os-5-firmware-release-note-v5-09-115/262310" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/o:wdc:my_cloud_firmware",
	 "cpe:/o:wdc:my_cloud_mirror_firmware",
	 "cpe:/o:wdc:my_cloud_ex2ultra_firmware",
	 "cpe:/o:wdc:my_cloud_ex2100_firmware",
	 "cpe:/o:wdc:my_cloud_ex4100_firmware",
	 "cpe:/o:wdc:my_cloud_dl2100_firmware",
	 "cpe:/o:wdc:my_cloud_dl4100_firmware",
	 "cpe:/o:wdc:my_cloud_pr2100_firmware",
	 "cpe:/o:wdc:my_cloud_pr4100_firmware" );
if(!infos = get_app_version_from_list( cpe_list: cpe_list, nofork: TRUE, version_regex: "^[0-9]+\\.[0-9]+\\.[0-9]+" )){
	exit( 0 );
}
version = infos["version"];
if(version_in_range( version: version, test_version: "5.0", test_version2: "5.08.115" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.09.115" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

