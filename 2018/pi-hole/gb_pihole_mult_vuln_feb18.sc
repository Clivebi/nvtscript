CPE = "cpe:/a:pi-hole:web";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108343" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2018-02-18 11:43:37 +0100 (Sun, 18 Feb 2018)" );
	script_name( "Pi-hole Ad-Blocker < 3.3 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_dependencies( "gb_pi-hole_detect.sc" );
	script_mandatory_keys( "pi-hole/detected" );
	script_xref( name: "URL", value: "https://pi-hole.net/2018/02/14/pi-hole-v3-3-released-its-extra-special/" );
	script_xref( name: "URL", value: "https://github.com/pi-hole/AdminLTE/pull/674" );
	script_tag( name: "summary", value: "This host is installed with the Pi-hole Ad-Blocker and
  is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - not using parameterized SQL queries.

  - XSS attack vectors in the php/auth.php and php/debug.php files." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote attackers to conduct SQL injection and XSS attacks." );
	script_tag( name: "affected", value: "Versions of the Pi-hole Ad-Blocker Web-Interface prior to 3.3." );
	script_tag( name: "solution", value: "Update the Pi-hole Ad-Blocker to version 3.3 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "3.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.3", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

