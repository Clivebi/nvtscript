CPE = "cpe:/a:osticket:osticket";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142721" );
	script_version( "2021-09-08T08:01:40+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 08:01:40 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-08-09 02:52:33 +0000 (Fri, 09 Aug 2019)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_cve_id( "CVE-2019-14748", "CVE-2019-14749", "CVE-2019-14750" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "osTicket < 1.10.7, 1.12.x < 1.12.1 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "osticket_detect.sc" );
	script_mandatory_keys( "osticket/installed" );
	script_tag( name: "summary", value: "osTicket is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "osTicket is prone to multiple vulnerabilities:

  - Persistent XSS vulnerability (CVE-2019-14748)

  - CSV injection vulnerability (CVE-2019-14749)

  - Stored XSS vulnerability (CVE-2019-14750)" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "osTicket prior to version 1.10.7 and 1.12." );
	script_tag( name: "solution", value: "Update to version 1.10.7, 1.12.1 or later." );
	script_xref( name: "URL", value: "https://github.com/osTicket/osTicket/releases/tag/v1.10.7" );
	script_xref( name: "URL", value: "https://github.com/osTicket/osTicket/releases/tag/v1.12.1" );
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
if(version_is_less( version: version, test_version: "1.10.7" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.10.7", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_is_equal( version: version, test_version: "1.12" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.12.1", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

