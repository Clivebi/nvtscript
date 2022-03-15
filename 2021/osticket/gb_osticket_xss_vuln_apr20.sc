CPE = "cpe:/a:osticket:osticket";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146206" );
	script_version( "2021-08-26T14:01:06+0000" );
	script_tag( name: "last_modification", value: "2021-08-26 14:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-07-02 02:56:46 +0000 (Fri, 02 Jul 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-01 18:33:00 +0000 (Thu, 01 Jul 2021)" );
	script_cve_id( "CVE-2020-22608", "CVE-2020-22609" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "osTicket < 1.12.6 Multiple XSS Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "osticket_detect.sc" );
	script_mandatory_keys( "osticket/installed" );
	script_tag( name: "summary", value: "osTicket is prone to multiple cross-site scripting (XSS)
  vulnerabilities." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2020-22608: XSS via the queue-name parameter in include/class.queue.php

  - CVE-2020-22609: XSS via the queue-name parameter to include/ajax.search.php" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "osTicket version 1.12.5 and prior." );
	script_tag( name: "solution", value: "Update to version 1.12.6 or later." );
	script_xref( name: "URL", value: "https://github.com/osTicket/osTicket/commit/6c724ea3fe352d10d457d334dc054ef81917fde1" );
	script_xref( name: "URL", value: "https://github.com/osTicket/osTicket/commit/d54cca0b265128f119b6c398575175cb10cf1754" );
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
if(version_is_less( version: version, test_version: "1.12.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.12.6", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

