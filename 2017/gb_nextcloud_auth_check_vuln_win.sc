CPE = "cpe:/a:nextcloud:nextcloud";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106706" );
	script_version( "2021-09-14T14:01:45+0000" );
	script_tag( name: "last_modification", value: "2021-09-14 14:01:45 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-03-30 14:13:45 +0700 (Thu, 30 Mar 2017)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:20:00 +0000 (Wed, 09 Oct 2019)" );
	script_cve_id( "CVE-2016-9464" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Nextcloud Authorization Check Vulnerability (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_nextcloud_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "nextcloud/installed", "Host/runs_windows" );
	script_tag( name: "summary", value: "Nextcloud is prone to an improper authorization check vulnerability on
removing shares" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The Sharing Backend as implemented in Nextcloud does differentiate between
shares to users and groups. In case of a received group share, users should be able to unshare the file to
themselves but not to the whole group." );
	script_tag( name: "affected", value: "Nextcloud Server prior to 9.0.54" );
	script_tag( name: "solution", value: "Update 9.0.54 or later versions." );
	script_xref( name: "URL", value: "https://nextcloud.com/security/advisory/?id=nc-sa-2016-007" );
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
if(version_is_less( version: version, test_version: "9.0.54" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.0.54" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

