if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108931" );
	script_version( "2020-09-02T13:22:40+0000" );
	script_tag( name: "last_modification", value: "2020-09-02 13:22:40 +0000 (Wed, 02 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-09-02 11:07:07 +0000 (Wed, 02 Sep 2020)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_cve_id( "CVE-2011-1575" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Western Digital My Cloud Multiple Products < 2.31.204 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wd_mycloud_consolidation.sc" );
	script_mandatory_keys( "wd-mycloud/detected" );
	script_xref( name: "URL", value: "https://community.wd.com/t/new-release-my-cloud-firmware-version-2-31-204-12-16-2019/244912" );
	script_tag( name: "summary", value: "Multiple Western Digital My Cloud products are prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following issues have been addressed:

  - Addressed a FTP vulnerability which could allow an unauthenticated attacker to inject commands prior to
  TLS authentication (CVE-2011-1575)

  - Resolved issue where remote access could not bedisabled" );
	script_tag( name: "affected", value: "Western Digital My Cloud with firmware versions prior to 2.31.204." );
	script_tag( name: "solution", value: "Update to firmware version 2.31.204 or later.

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
if(version_is_less( version: version, test_version: "2.31.204" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.31.204" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

