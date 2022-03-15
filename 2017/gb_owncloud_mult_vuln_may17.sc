CPE = "cpe:/a:owncloud:owncloud";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106967" );
	script_version( "2021-09-08T12:01:36+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 12:01:36 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-07-19 13:10:50 +0700 (Wed, 19 Jul 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-08-08 15:20:00 +0000 (Tue, 08 Aug 2017)" );
	script_cve_id( "CVE-2017-9339", "CVE-2017-9340" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "ownCloud Multiple Vulnerabilities May17" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_owncloud_detect.sc" );
	script_mandatory_keys( "owncloud/installed" );
	script_tag( name: "summary", value: "ownCloud is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "ownCloud is prone to multiple vulnerabilities:

  - Share tokens for public calendars disclosed. (CVE-2017-9339)

  - Normal user can somehow make admin to delete shared folders. (CVE-2017-9340)" );
	script_tag( name: "solution", value: "Update to ownCloud Server 10.0.2 or later versions." );
	script_xref( name: "URL", value: "https://owncloud.org/security/advisory/?id=oc-sa-2017-005" );
	script_xref( name: "URL", value: "https://owncloud.org/security/advisory/?id=oc-sa-2017-006" );
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
if(IsMatchRegexp( version, "^10\\.0" )){
	if(version_is_less( version: version, test_version: "10.0.2" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "10.0.2" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

