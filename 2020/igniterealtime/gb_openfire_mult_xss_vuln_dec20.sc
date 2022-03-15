CPE = "cpe:/a:igniterealtime:openfire";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145064" );
	script_version( "2021-07-13T02:01:14+0000" );
	script_tag( name: "last_modification", value: "2021-07-13 02:01:14 +0000 (Tue, 13 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-12-17 08:48:32 +0000 (Thu, 17 Dec 2020)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-14 21:45:00 +0000 (Mon, 14 Dec 2020)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "NoneAvailable" );
	script_cve_id( "CVE-2020-35127", "CVE-2020-35199", "CVE-2020-35200", "CVE-2020-35201", "CVE-2020-35202" );
	script_name( "Openfire <= 4.6.4 Multiple XSS Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_openfire_detect.sc" );
	script_mandatory_keys( "OpenFire/Installed" );
	script_tag( name: "summary", value: "Openfire is prone to multiple cross-site scripting (XSS) vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaws exist in various parameters of the application." );
	script_tag( name: "impact", value: "Successful exploitation would allow a remote attacker
  to inject arbitrary script commands into the affected application." );
	script_tag( name: "affected", value: "Openfire version 4.6.4 and probably prior." );
	script_tag( name: "solution", value: "No known solution is available as of 08th July, 2021.
  Information regarding this issue will be updated once solution details are available." );
	script_xref( name: "URL", value: "https://discourse.igniterealtime.org/t/openfire-4-6-0-has-stored-xss-vulnerabilities/89276" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/49233" );
	script_xref( name: "URL", value: "https://discourse.igniterealtime.org/t/openfire-4-6-0-has-reflective-xss-vulnerabilities/89296" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/49234" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/49235" );
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
version = infos["version"];
location = infos["location"];
if(version_is_less_equal( version: version, test_version: "4.6.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

