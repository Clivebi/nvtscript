if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106107" );
	script_version( "2020-04-01T10:41:43+0000" );
	script_tag( name: "last_modification", value: "2020-04-01 10:41:43 +0000 (Wed, 01 Apr 2020)" );
	script_tag( name: "creation_date", value: "2016-06-23 12:12:32 +0700 (Thu, 23 Jun 2016)" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:C/A:C" );
	script_cve_id( "CVE-2015-6464", "CVE-2015-6465", "CVE-2015-6466" );
	script_name( "Moxa EDS-405A/408A Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_moxa_eds_detect.sc" );
	script_mandatory_keys( "moxa_eds/detected" );
	script_xref( name: "URL", value: "http://www.moxa.com/support/download.aspx?type=support&id=328" );
	script_tag( name: "summary", value: "Moxa EDS-405A and EDS-408A is prone to multiple vulnerabilies." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Moxa EDS-405A and EDS-408A is prone to multiple vulnerabilies:

  The administrative web interface on Moxa EDS-405A and EDS-408A switches with firmware before 3.6 allows
  remote authenticated users to bypass a read-only protection mechanism by using Firefox with a web-developer
  plugin. (CVE-2015-6464)

  The GoAhead web server on Moxa EDS-405A and EDS-408A switches with firmware before 3.6 allows remote
  authenticated users to cause a denial of service (reboot) via a crafted URL. (CVE-2015-6465)

  Cross-site scripting (XSS) vulnerability in the Diagnosis Ping feature in the administrative web interface
  on Moxa EDS-405A and EDS-408A switches with firmware before 3.6 allows remote attackers to inject arbitrary
  web script or HTML via an unspecified field. (CVE-2015-6466)" );
	script_tag( name: "impact", value: "An authenticated attacker may bypass security restrictions or cause a
  denial of service." );
	script_tag( name: "affected", value: "Version prior to 3.6." );
	script_tag( name: "solution", value: "Upgrade to Version 3.6 or later." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/a:moxa:eds-405a",
	 "cpe:/a:moxa:eds-408a" );
if(!infos = get_app_port_from_list( cpe_list: cpe_list )){
	exit( 0 );
}
CPE = infos["cpe"];
port = infos["port"];
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "3.6" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.6", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

