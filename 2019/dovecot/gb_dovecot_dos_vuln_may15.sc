CPE = "cpe:/a:dovecot:dovecot";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142827" );
	script_version( "2021-08-31T08:01:19+0000" );
	script_tag( name: "last_modification", value: "2021-08-31 08:01:19 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-08-30 05:19:22 +0000 (Fri, 30 Aug 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-10-05 15:17:00 +0000 (Thu, 05 Oct 2017)" );
	script_cve_id( "CVE-2015-3420" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Dovecot < 2.2.17 DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_dovecot_consolidation.sc" );
	script_mandatory_keys( "dovecot/detected" );
	script_tag( name: "summary", value: "Dovecot is prone to a denial of service vulnerability when SSLv3 is disabled." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Dovecot prior to version 2.2.17." );
	script_tag( name: "solution", value: "Update to version 2.2.17 or later." );
	script_xref( name: "URL", value: "https://dovecot.org/pipermail/dovecot-news/2015-May/000292.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "2.2.17" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.2.17", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

