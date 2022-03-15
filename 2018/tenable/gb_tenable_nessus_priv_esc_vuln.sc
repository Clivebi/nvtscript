CPE = "cpe:/a:tenable:nessus";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813061" );
	script_version( "2021-09-29T12:07:39+0000" );
	script_cve_id( "CVE-2018-1141" );
	script_tag( name: "cvss_base", value: "4.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-29 12:07:39 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-04-03 12:17:22 +0530 (Tue, 03 Apr 2018)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Tenable Nessus Non-Default Directory Installation Privilege Escalation Vulnerability (TNS-2018-01)" );
	script_tag( name: "summary", value: "Nessus is prone to a local privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists when nessus is installed
  in a non-default directory, the system does not enforce secure permissions for
  sub-directories." );
	script_tag( name: "impact", value: "Successful exploitation will allow for local
  privilege escalation if users had not secured the directories in the installation
  location." );
	script_tag( name: "affected", value: "Nessus versions prior to 7.0.3." );
	script_tag( name: "solution", value: "Update to version 7.0.3 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.securitytracker.com/id/1040557" );
	script_xref( name: "URL", value: "https://www.tenable.com/security/tns-2018-01" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_nessus_web_server_detect.sc" );
	script_mandatory_keys( "nessus/installed" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "7.0.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "7.0.3", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

