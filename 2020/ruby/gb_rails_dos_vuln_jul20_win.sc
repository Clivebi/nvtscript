if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113716" );
	script_version( "2021-07-07T11:00:41+0000" );
	script_tag( name: "last_modification", value: "2021-07-07 11:00:41 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-07-06 10:19:34 +0000 (Mon, 06 Jul 2020)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-05 02:15:00 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2020-8185" );
	script_name( "Ruby on Rails < 6.0.3.2 DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_rails_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "rails/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "Ruby on Rails is prone to a denial of service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An untrusted user may run any pending migration in production." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to
  render legitimate users unable to use the application." );
	script_tag( name: "affected", value: "Ruby on Rails through version 6.0.3.1." );
	script_tag( name: "solution", value: "Update to version 6.0.3.2." );
	script_xref( name: "URL", value: "https://hackerone.com/reports/899069" );
	exit( 0 );
}
CPE = "cpe:/a:rubyonrails:rails";
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
if(version_is_less( version: version, test_version: "6.0.3.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.0.3.2", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

