if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112562" );
	script_version( "2021-09-07T14:01:38+0000" );
	script_tag( name: "last_modification", value: "2021-09-07 14:01:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-04-10 12:04:40 +0200 (Wed, 10 Apr 2019)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-16 15:35:00 +0000 (Tue, 16 Apr 2019)" );
	script_cve_id( "CVE-2019-11025" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Cacti < 1.2.3 XSS Vulnerability (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "cacti_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "cacti/installed", "Host/runs_windows" );
	script_tag( name: "summary", value: "Cacti is prone to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "No escaping occurs in clearFilter() in utilities.php before printing
  out the value of the SNMP community string (SNMP Options) in the View poller cache, which leads to XSS." );
	script_tag( name: "affected", value: "Cacti prior to version 1.2.3." );
	script_tag( name: "solution", value: "Update to version 1.2.3 or later." );
	script_xref( name: "URL", value: "https://github.com/Cacti/cacti/issues/2581" );
	exit( 0 );
}
CPE = "cpe:/a:cacti:cacti";
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
if(version_is_less( version: version, test_version: "1.2.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.2.3", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

