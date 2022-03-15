if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108919" );
	script_version( "2021-08-16T09:00:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-16 09:00:57 +0000 (Mon, 16 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-09-02 11:07:07 +0000 (Wed, 02 Sep 2020)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-16 12:15:00 +0000 (Wed, 16 Jun 2021)" );
	script_cve_id( "CVE-2014-3566" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Western Digital My Cloud Multiple Products 'POODLE' Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wd_mycloud_consolidation.sc" );
	script_mandatory_keys( "wd-mycloud/detected" );
	script_tag( name: "summary", value: "Multiple Western Digital My Cloud products are prone to an
  information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following issues have been addressed:

  - Resolved issue of POODLE (CVE-2014-3566) SSLv3 security vulnerability" );
	script_tag( name: "affected", value: "Western Digital My Cloud with firmware versions prior to 1.05.36,
  1.06.x prior to 1.06.133 and 2.x prior to 2.10.302." );
	script_tag( name: "solution", value: "Update to firmware version 1.05.36, 1.06.133, 2.10.302 or later.

  Note: Some My Cloud products are already end-of-life and doesn't receive any updates anymore." );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/o:wdc:my_cloud_firmware",
	 "cpe:/o:wdc:my_cloud_mirror_firmware",
	 "cpe:/o:wdc:my_cloud_pr2100_firmware",
	 "cpe:/o:wdc:my_cloud_pr4100_firmware",
	 "cpe:/o:wdc:my_cloud_ex2ultra_firmware",
	 "cpe:/o:wdc:my_cloud_ex2_firmware",
	 "cpe:/o:wdc:my_cloud_ex4_firmware",
	 "cpe:/o:wdc:my_cloud_ex2100_firmware",
	 "cpe:/o:wdc:my_cloud_ex4100_firmware",
	 "cpe:/o:wdc:my_cloud_dl2100_firmware",
	 "cpe:/o:wdc:my_cloud_dl4100_firmware" );
if(!infos = get_app_version_from_list( cpe_list: cpe_list, nofork: TRUE, version_regex: "^[0-9]+\\.[0-9]+\\.[0-9]+" )){
	exit( 0 );
}
version = infos["version"];
if( version_is_less( version: version, test_version: "1.05.36" ) ){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.05.36" );
	security_message( port: 0, data: report );
	exit( 0 );
}
else {
	if( IsMatchRegexp( version, "^1\\.06\\." ) && version_is_less( version: version, test_version: "1.06.133" ) ){
		report = report_fixed_ver( installed_version: version, fixed_version: "1.06.133" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
	else {
		if(IsMatchRegexp( version, "^2\\.[01]" ) && version_is_less( version: version, test_version: "2.10.302" )){
			report = report_fixed_ver( installed_version: version, fixed_version: "2.10.302" );
			security_message( port: 0, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

