CPE = "cpe:/a:paessler:prtg_network_monitor";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143451" );
	script_version( "2021-08-16T12:00:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-16 12:00:57 +0000 (Mon, 16 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-02-05 03:57:53 +0000 (Wed, 05 Feb 2020)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_cve_id( "CVE-2019-19119", "CVE-2019-11073" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "PRTG Network Monitor < 19.4.54.1506 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_prtg_network_monitor_detect.sc" );
	script_mandatory_keys( "prtg_network_monitor/installed" );
	script_tag( name: "summary", value: "PRTG Network Monitor is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "PRTG Network Monitor is prone to multiple vulnerabilities:

  - Due to insufficient access control on local registry keys for the Core Server Service, a non-administrative
    user on the local machine is able to access administrative credentials. (CVE-2019-19119)

  - A Remote Code Execution vulnerability exists that allows attackers to execute code due to insufficient
    sanitization when passing arguments to the HttpTransactionSensor.exe binary. In order to exploit the
    vulnerability, remote authenticated administrators need to create a new HTTP Transaction Sensor and set
    specific settings when the sensor is executed. (CVE-2019-11073)

  - A Remote Code Execution (RCE) vulnerability of the PRTG core server." );
	script_tag( name: "affected", value: "PRTG Network Monitor prior to version 19.4.54.1506." );
	script_tag( name: "solution", value: "Update to version 19.4.54.1506 or later." );
	script_xref( name: "URL", value: "https://www.paessler.com/prtg/history/stable" );
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
if(version_is_less( version: version, test_version: "19.4.54.1506" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "19.4.54.1506", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

