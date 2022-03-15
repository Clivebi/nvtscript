CPE = "cpe:/a:nextcloud:nextcloud";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143456" );
	script_version( "2021-08-12T09:01:18+0000" );
	script_tag( name: "last_modification", value: "2021-08-12 09:01:18 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-02-05 07:35:03 +0000 (Wed, 05 Feb 2020)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-11 18:43:00 +0000 (Tue, 11 Feb 2020)" );
	script_cve_id( "CVE-2019-15616" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Nextcloud Server 16.x DNS Pollution Vulnerability (NC-SA-2020-005)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_nextcloud_detect.sc" );
	script_mandatory_keys( "nextcloud/installed" );
	script_tag( name: "summary", value: "Nextcloud Server is prone to a DNS pollution vulnerability." );
	script_tag( name: "insight", value: "Dangling remote share attempts in Nextcloud 16 allow a DNS pollution when
  running long." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Nextcloud server 16.x." );
	script_tag( name: "solution", value: "Update to version 17.0.0 or later." );
	script_xref( name: "URL", value: "https://nextcloud.com/security/advisory/?id=NC-SA-2020-005" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(IsMatchRegexp( version, "^16\\." )){
	report = report_fixed_ver( installed_version: version, fixed_version: "17.0.0", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

