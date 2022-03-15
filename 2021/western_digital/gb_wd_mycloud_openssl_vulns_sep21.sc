if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117657" );
	script_version( "2021-09-27T09:22:59+0000" );
	script_tag( name: "last_modification", value: "2021-09-27 09:22:59 +0000 (Mon, 27 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-13 06:08:15 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-31 16:37:00 +0000 (Tue, 31 Aug 2021)" );
	script_cve_id( "CVE-2021-3711", "CVE-2021-3712" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Western Digital My Cloud Multiple Products 5.0 < 5.17.107 OpenSSL Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_wd_mycloud_consolidation.sc" );
	script_mandatory_keys( "wd-mycloud/detected" );
	script_tag( name: "summary", value: "Multiple Western Digital My Cloud products are prone to multiple
  vulnerabilities in OpenSSL." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Updated OpenSSL to version 1.1.1d deb10u7 to resolve remote code
  execution (CVE-2021-3711) and denial of service (CVE-2021-3712) vulnerabilities." );
	script_tag( name: "affected", value: "Western Digital My Cloud PR2100, My Cloud PR4100, My Cloud EX2
  Ultra, My Cloud EX2100, My Cloud EX4100, My Cloud Mirror Gen 2, My Cloud DL2100, My Cloud DL4100,
  My Cloud (P/N: WDBCTLxxxxxx-10) and WD Cloud (Japan) with firmware versions prior to 5.17.107." );
	script_tag( name: "solution", value: "Update to firmware version 5.17.107 or later." );
	script_xref( name: "URL", value: "https://community.wd.com/t/my-cloud-os-5-firmware-release-note-v5-17-107/270599" );
	script_xref( name: "URL", value: "https://www.westerndigital.com/support/productsecurity/wdc-21011-my-cloud-firmware-version-5-17-107" );
	script_xref( name: "URL", value: "https://www.openssl.org/news/secadv/20210824.txt" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/o:wdc:wd_cloud_firmware",
	 "cpe:/o:wdc:my_cloud_firmware",
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
if(version_in_range( version: version, test_version: "5.0", test_version2: "5.16.105" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.17.107" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

