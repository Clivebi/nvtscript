CPE = "cpe:/o:mikrotik:routeros";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144720" );
	script_version( "2021-07-22T11:01:40+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 11:01:40 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-10-08 05:18:18 +0000 (Thu, 08 Oct 2020)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-15 13:03:00 +0000 (Thu, 15 Oct 2020)" );
	script_cve_id( "CVE-2019-16160" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "MikroTik RouterOS < 6.45.5 DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_mikrotik_router_routeros_consolidation.sc" );
	script_mandatory_keys( "mikrotik/detected" );
	script_tag( name: "summary", value: "MikroTik RouterOS is prone to a denial of service vulnerability due to an
  integer overflow in the SMB server." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "MikroTik RouterOS prior to version 6.45.5." );
	script_tag( name: "solution", value: "Update to version 6.45.5 or later." );
	script_xref( name: "URL", value: "https://forum.mikrotik.com/viewtopic.php?t=151603" );
	script_xref( name: "URL", value: "https://gist.github.com/thebabush/3c71fc5001f8865e3ad579e80680ce24" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "6.45.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.45.5" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

