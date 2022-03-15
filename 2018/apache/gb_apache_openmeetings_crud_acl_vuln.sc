CPE = "cpe:/a:apache:openmeetings";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108352" );
	script_version( "2021-06-15T02:54:56+0000" );
	script_tag( name: "last_modification", value: "2021-06-15 02:54:56 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-26 14:17:13 +0100 (Mon, 26 Feb 2018)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_cve_id( "CVE-2018-1286" );
	script_name( "Apache OpenMeetings 'CVE-2018-1286' Insufficient Access Controls Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_openmeetings_detect.sc" );
	script_require_ports( "Services/www", 5080 );
	script_mandatory_keys( "Apache/Openmeetings/Installed" );
	script_xref( name: "URL", value: "https://openmeetings.apache.org/security.html" );
	script_tag( name: "summary", value: "Apache OpenMeetings is prone to an insufficient access controls
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists because CRUD operations on privileged users
  where not password protected." );
	script_tag( name: "impact", value: "The flaw allows an authenticated attacker to deny service for
  privileged users." );
	script_tag( name: "affected", value: "Apache OpenMeetings version 3.0.0 up to 4.0.1" );
	script_tag( name: "solution", value: "Update Apache OpenMeetings to version 4.0.2 or later." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "3.0.0", test_version2: "4.0.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "4.0.2" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

