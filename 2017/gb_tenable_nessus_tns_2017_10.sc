CPE = "cpe:/a:tenable:nessus";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108148" );
	script_version( "2021-09-09T13:03:05+0000" );
	script_cve_id( "CVE-2017-7849", "CVE-2017-7850" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-09 13:03:05 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-04-20 08:08:04 +0200 (Thu, 20 Apr 2017)" );
	script_name( "Tenable Nessus 6.10.x < 6.10.5 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_nessus_web_server_detect.sc" );
	script_mandatory_keys( "nessus/installed" );
	script_require_ports( "Services/www", 8834 );
	script_xref( name: "URL", value: "https://www.tenable.com/security/tns-2017-10" );
	script_tag( name: "summary", value: "This host is installed with Nessus and is prone to
  multiple vulnerabilities when running in agent mode." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - a local denial of service condition due to insecure permissions when running in Agent Mode

  - a local privilege escalation issue due to insecure permissions when running in Agent Mode" );
	script_tag( name: "affected", value: "Tenable Nessus versions 6.10.x before 6.10.5 when running in agent mode." );
	script_tag( name: "solution", value: "Upgrade Tenable Nessus to 6.10.5 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "6.10.0", test_version2: "6.10.4" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "6.10.5" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

