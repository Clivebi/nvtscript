if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113048" );
	script_version( "2021-09-09T08:01:35+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 08:01:35 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-09 13:53:54 +0100 (Thu, 09 Nov 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-13 17:06:00 +0000 (Mon, 13 Nov 2017)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2012-6707" );
	script_name( "WordPress through 4.8.2 Weak Password Hash Algorithm" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_tag( name: "summary", value: "WordPress through 4.8.2 uses a Weak MD5 password hasing algorithm" );
	script_tag( name: "vuldetect", value: "This script checks if a vulnerable version is present on the host." );
	script_tag( name: "impact", value: "The weak algorithm would allow an attacker with access to password hashes to more easily bruteforce those to acquire the cleartext passwords." );
	script_tag( name: "affected", value: "WordPress through version 4.8.2" );
	script_tag( name: "solution", value: "Update WordPress to version 4.8.3" );
	script_xref( name: "URL", value: "https://core.trac.wordpress.org/ticket/21022" );
	exit( 0 );
}
CPE = "cpe:/a:wordpress:wordpress";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "4.8.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.8.3" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

