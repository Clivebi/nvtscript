CPE = "cpe:/a:osticket:osticket";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142720" );
	script_version( "2021-09-08T08:01:40+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 08:01:40 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-08-09 02:47:26 +0000 (Fri, 09 Aug 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-10 12:35:00 +0000 (Wed, 10 Jul 2019)" );
	script_cve_id( "CVE-2019-13397" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "osTicket < 1.10.2 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "osticket_detect.sc" );
	script_mandatory_keys( "osticket/installed" );
	script_tag( name: "summary", value: "osTicket is prone to a cross-site scripting vulnerability." );
	script_tag( name: "insight", value: "Unauthenticated Stored XSS allows a remote attacker to gain admin privileges
  by injecting arbitrary web script or HTML via arbitrary file extension while creating a support ticket." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "osTicket version 1.10.1 and prior." );
	script_tag( name: "solution", value: "Update to version 1.10.2 or later." );
	script_xref( name: "URL", value: "https://github.com/osTicket/osTicket/releases/tag/v1.10.2" );
	script_xref( name: "URL", value: "https://medium.com/@sarapremashish/osticket-1-10-1-unauthenticated-stored-xss-allows-an-attacker-to-gain-admin-privileges-6a0348761a3a" );
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
if(version_is_less( version: version, test_version: "1.10.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.10.2", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

