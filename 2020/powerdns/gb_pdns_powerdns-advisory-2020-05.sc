CPE = "cpe:/a:powerdns:authoritative_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144705" );
	script_version( "2021-08-12T06:00:50+0000" );
	script_tag( name: "last_modification", value: "2021-08-12 06:00:50 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-10-05 05:00:31 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-23 22:15:00 +0000 (Wed, 23 Dec 2020)" );
	script_cve_id( "CVE-2020-17482" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "PowerDNS Authoritative Server Information Disclosure Vulnerability (2020-05)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "pdns_version.sc" );
	script_mandatory_keys( "powerdns/authoritative_server/installed" );
	script_tag( name: "summary", value: "PowerDNS Authoritative Server is prone to an information disclosure vulnerability." );
	script_tag( name: "insight", value: "An issue has been found in PowerDNS Authoritative Server where an authorized
  user with the ability to insert crafted records into a zone might be able to leak the content of uninitialized
  memory. Such a user could be a customer inserting data via a control panel, or somebody with access to the REST
  API. Crafted records cannot be inserted via AXFR." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "PowerDNS Authoritative prior to version 4.1.14, version 4.2.x prior to 4.2.3 and
  version 4.3.0." );
	script_tag( name: "solution", value: "Update to version 4.1.14, 4.2.3, 4.3.1 or later." );
	script_xref( name: "URL", value: "https://doc.powerdns.com/authoritative/security-advisories/powerdns-advisory-2020-05.html" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_proto( cpe: CPE, port: port )){
	exit( 0 );
}
version = infos["version"];
proto = infos["proto"];
if(version_is_less( version: version, test_version: "4.1.14" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.1.14" );
	security_message( data: report, port: port, proto: proto );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.2.0", test_version2: "4.2.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.2.3" );
	security_message( data: report, port: port, proto: proto );
	exit( 0 );
}
if(version_is_equal( version: version, test_version: "4.3.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.3.1" );
	security_message( data: report, port: port, proto: proto );
	exit( 0 );
}
exit( 99 );

