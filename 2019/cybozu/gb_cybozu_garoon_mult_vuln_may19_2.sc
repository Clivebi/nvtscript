if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113399" );
	script_version( "2021-09-07T08:01:28+0000" );
	script_tag( name: "last_modification", value: "2021-09-07 08:01:28 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-05-29 13:44:16 +0000 (Wed, 29 May 2019)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-20 15:49:00 +0000 (Mon, 20 May 2019)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2019-5933", "CVE-2019-5934" );
	script_name( "Cybozu Garoon 4.x.x <= 4.10.0 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_cybozu_products_detect.sc" );
	script_mandatory_keys( "CybozuGaroon/Installed" );
	script_tag( name: "summary", value: "Cybozu Garoon is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - Remote authenticated attackers may bypass access restriction to
    view the Bulletin Board without view privileges via the application 'Bulletin'

  - Attackers with administrator rights may execute arbitrary SQL commands via
    the Log Search function of application 'logging'" );
	script_tag( name: "affected", value: "Cybozu Garoon version 4.0.0 through 4.10.0." );
	script_tag( name: "solution", value: "Update to version 4.10.1." );
	script_xref( name: "URL", value: "https://kb.cybozu.support/article/35306/" );
	exit( 0 );
}
CPE = "cpe:/a:cybozu:garoon";
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
if(version_in_range( version: version, test_version: "4.0.0", test_version2: "4.10.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.10.1", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

