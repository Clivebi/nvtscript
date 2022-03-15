CPE = "cpe:/a:opencast:opencast";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112866" );
	script_version( "2021-08-24T09:01:06+0000" );
	script_tag( name: "last_modification", value: "2021-08-24 09:01:06 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-02-19 12:10:11 +0000 (Fri, 19 Feb 2021)" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-26 04:04:00 +0000 (Fri, 26 Feb 2021)" );
	script_cve_id( "CVE-2021-21318" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OpenCast < 9.2 Access Control Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_opencast_detect.sc" );
	script_mandatory_keys( "opencast/detected" );
	script_tag( name: "summary", value: "OpenCast is prone to an access control vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Publishing an episode with strict access rules will overwrite
  the currently set series access." );
	script_tag( name: "impact", value: "Successful exploitation could lead to a denial of access for all users
  without superuser privileges, effectively hiding the series." );
	script_tag( name: "affected", value: "OpenCast versions prior to 9.2." );
	script_tag( name: "solution", value: "Update OpenCast to version 9.2 or later." );
	script_xref( name: "URL", value: "https://github.com/opencast/opencast/commit/b18c6a7f81f08ed14884592a6c14c9ab611ad450" );
	script_xref( name: "URL", value: "https://github.com/opencast/opencast/security/advisories/GHSA-vpc2-3wcv-qj4w" );
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
if(version_is_less( version: version, test_version: "9.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.2", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

