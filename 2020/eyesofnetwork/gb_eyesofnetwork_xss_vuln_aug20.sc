CPE = "cpe:/a:eyes_of_network:eyes_of_network";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144502" );
	script_version( "2021-08-12T09:01:18+0000" );
	script_tag( name: "last_modification", value: "2021-08-12 09:01:18 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-08-31 02:45:16 +0000 (Mon, 31 Aug 2020)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-02 16:57:00 +0000 (Wed, 02 Sep 2020)" );
	script_cve_id( "CVE-2020-24390" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Eyes Of Network (EON) < 5.3-7 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_eyesofnetwork_detect.sc" );
	script_mandatory_keys( "eyesofnetwork/detected" );
	script_tag( name: "summary", value: "Eyes Of Network (EON) is prone to a cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "eonweb in EyesOfNetwork does not properly escape the username on the
  /module/admin_logs page, which might allow pre-authentication stored XSS during login/logout logs recording." );
	script_tag( name: "affected", value: "Eyes Of Network prior to version 5.3-7." );
	script_tag( name: "solution", value: "Update to version 5.3-7 or later." );
	script_xref( name: "URL", value: "https://github.com/EyesOfNetworkCommunity/eonweb/releases/tag/5.3-7" );
	script_xref( name: "URL", value: "https://www.eyesofnetwork.com/en/news/en-CVE-2020-24390" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "5.3.7" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.3-7" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

