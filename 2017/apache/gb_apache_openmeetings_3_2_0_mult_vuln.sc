if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112063" );
	script_version( "2021-09-13T11:01:38+0000" );
	script_tag( name: "last_modification", value: "2021-09-13 11:01:38 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-10-05 14:45:22 +0200 (Thu, 05 Oct 2017)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2017-7663", "CVE-2017-7682" );
	script_bugtraq_id( 99577 );
	script_name( "Apache OpenMeetings 3.2.x Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_openmeetings_detect.sc" );
	script_require_ports( "Services/www", 5080 );
	script_mandatory_keys( "Apache/Openmeetings/Installed" );
	script_tag( name: "summary", value: "Apache OpenMeetings 3.2.x is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Apache OpenMeetings is prone to the following vulnerabilities:

  - Both global and Room chat are vulnerable to XSS attack (CVE-2017-7663).

  - Apache OpenMeetings is vulnerable to parameter manipulation attacks, as a result attacker has access to restricted areas (CVE-2017-7682)." );
	script_tag( name: "affected", value: "Apache OpenMeetings versions 3.2.x" );
	script_tag( name: "solution", value: "Update your software to version 3.3.0 to fix the issue" );
	script_xref( name: "URL", value: "https://openmeetings.apache.org/security.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe = "cpe:/a:apache:openmeetings";
if(!port = get_app_port( cpe: cpe )){
	exit( 0 );
}
if(!ver = get_app_version( cpe: cpe, port: port )){
	exit( 0 );
}
if(version_in_range( version: ver, test_version: "3.2.0", test_version2: "3.2.1" )){
	report = report_fixed_ver( installed_version: ver, fixed_version: "3.3.0" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

