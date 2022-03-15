CPE = "cpe:/a:gnu:mailman";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143871" );
	script_version( "2021-08-12T09:01:18+0000" );
	script_tag( name: "last_modification", value: "2021-08-12 09:01:18 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-05-08 07:20:31 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-27 16:15:00 +0000 (Tue, 27 Oct 2020)" );
	script_cve_id( "CVE-2020-12108" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Mailman < 2.1.31 Content Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "mailman_detect.sc" );
	script_mandatory_keys( "gnu_mailman/detected" );
	script_tag( name: "summary", value: "Mailman is prone to a content injection vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Mailman versions up to and including 2.1.30." );
	script_tag( name: "solution", value: "Update to version 2.1.31 or later." );
	script_xref( name: "URL", value: "https://bugs.launchpad.net/mailman/+bug/1873722" );
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
if(version_is_less( version: version, test_version: "2.1.31" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.1.31", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

