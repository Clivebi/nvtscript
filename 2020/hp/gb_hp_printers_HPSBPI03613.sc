CPE = "cpe:/h:hp:deskjet_ink_advantage_3630_all-in-one_printer_series";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143348" );
	script_version( "2021-07-22T11:01:40+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 11:01:40 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-01-13 06:26:25 +0000 (Mon, 13 Jan 2020)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-22 18:29:00 +0000 (Wed, 22 Jan 2020)" );
	script_cve_id( "CVE-2019-6319", "CVE-2019-6320" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "HP DeskJet 3630 Printers CSRF Vulnerability (HPSBPI03613)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_hp_printer_detect.sc" );
	script_mandatory_keys( "hp_printer/installed" );
	script_tag( name: "summary", value: "Certain HP DeskJet 3630 All-in-One Printers have a Cross-Site Request Forgery
  (CSRF) vulnerability that could lead to a denial of service (DOS) or device misconfiguration." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "HP DeskJet 3630 All-in-One Printers." );
	script_tag( name: "solution", value: "Update to firmware version SWP1FN1912BR or later." );
	script_xref( name: "URL", value: "https://support.hp.com/us-en/document/c06308143" );
	exit( 0 );
}
require("host_details.inc.sc");
require("revisions-lib.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(revcomp( a: version, b: "SWP1FN1912BR" ) < 0){
	report = report_fixed_ver( installed_version: version, fixed_version: "SWP1FN1912BR" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

