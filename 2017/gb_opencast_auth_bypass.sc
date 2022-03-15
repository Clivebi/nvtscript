if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113062" );
	script_version( "2021-09-15T09:01:43+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 09:01:43 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-12-06 14:58:59 +0100 (Wed, 06 Dec 2017)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2017-1000221" );
	script_name( "Opencast Authentication Bypass Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_opencast_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "opencast/detected" );
	script_tag( name: "summary", value: "Opencast through version 2.2.3 is prone to an authentication bypass vulnerability." );
	script_tag( name: "vuldetect", value: "The script checks if a vulnerable system is present on the target host." );
	script_tag( name: "insight", value: "If user names overlap, the Opencast search service used for publication to the media modules and players will handle the access control incorrectly so that users only need to match part of the user name used for the access restriction." );
	script_tag( name: "impact", value: "Successful exploitation would allow an authenticatedattacker to access files that would normally require higher privileges." );
	script_tag( name: "affected", value: "Opencast through version 2.2.3" );
	script_tag( name: "solution", value: "Update Opencast to version 2.2.4 or 2.3.0" );
	script_xref( name: "URL", value: "https://opencast.jira.com/browse/MH-11862" );
	exit( 0 );
}
CPE = "cpe:/a:opencast:opencast";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "2.2.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.2.4" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

