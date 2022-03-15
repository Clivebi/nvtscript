if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112592" );
	script_version( "2021-09-07T08:01:28+0000" );
	script_tag( name: "last_modification", value: "2021-09-07 08:01:28 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-06-03 17:06:00 +0200 (Mon, 03 Jun 2019)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-29 18:38:00 +0000 (Wed, 29 May 2019)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2016-10753" );
	script_name( "e107 < 2.1.3 SQL Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "e107_detect.sc" );
	script_mandatory_keys( "e107/installed" );
	script_tag( name: "summary", value: "e107 is prone to an SQL injection vulnerability through object injection." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "e107 allows PHP Object Injection with resultant SQL injection, because usersettings.php uses unserialize without an HMAC." );
	script_tag( name: "affected", value: "e107 versions through 2.1.2." );
	script_tag( name: "solution", value: "Update to version 2.1.3 or later." );
	script_xref( name: "URL", value: "https://blog.ripstech.com/2016/e107-sql-injection-through-object-injection/" );
	exit( 0 );
}
CPE = "cpe:/a:e107:e107";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
path = infos["location"];
if(version_is_less( version: version, test_version: "2.1.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.1.3", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

