CPE = "cpe:/a:znc:znc";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144112" );
	script_version( "2021-07-07T02:00:46+0000" );
	script_tag( name: "last_modification", value: "2021-07-07 02:00:46 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-06-16 05:16:42 +0000 (Tue, 16 Jun 2020)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-03 03:15:00 +0000 (Fri, 03 Jul 2020)" );
	script_cve_id( "CVE-2020-13775" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "ZNC < 1.8.1 DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_znc_consolidation.sc" );
	script_mandatory_keys( "znc/detected" );
	script_tag( name: "summary", value: "ZNC is prone to a denial of service vulnerability." );
	script_tag( name: "insight", value: "ZNC allows authenticated users to trigger an application crash (with a NULL
  pointer dereference) if echo-message is not enabled and there is no network." );
	script_tag( name: "affected", value: "ZNC version 1.8.0 and prior." );
	script_tag( name: "solution", value: "Update to version 1.8.1 or later." );
	script_xref( name: "URL", value: "https://github.com/znc/znc/releases/tag/znc-1.8.1" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "1.8.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.8.1" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

