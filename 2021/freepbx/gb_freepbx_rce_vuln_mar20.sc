CPE = "cpe:/a:freepbx:freepbx";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112892" );
	script_version( "2021-08-20T06:00:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-20 06:00:57 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-06-02 10:57:11 +0000 (Wed, 02 Jun 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-11 19:40:00 +0000 (Fri, 11 Jun 2021)" );
	script_cve_id( "CVE-2020-10666" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "FreePBX 13.x <= 13.0.93.2, 14.x <= 14.0.22.2, 15.x <= 15.0.19.2 RCE Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_freepbx_detect.sc" );
	script_mandatory_keys( "freepbx/installed" );
	script_tag( name: "summary", value: "FreePBX is prone to a remote code execution (RCE) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Remote execution vulnerabilities exist in the Restapps / Phone
  apps module. A URL variable could potentially get passed into an AMI command, allowing for RCE." );
	script_tag( name: "affected", value: "FreePBX 13.x through 13.0.93.2, 14.x through 14.0.22.2
  and 15.x through 15.0.19.2." );
	script_tag( name: "solution", value: "Updates are available. Please see the referenced advisory for
  more information." );
	script_xref( name: "URL", value: "https://wiki.freepbx.org/display/FOP/2020-03-12+SECURITY%3A+Potential+Rest+Phone+Apps+RCE" );
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
if(version_in_range( version: version, test_version: "13", test_version2: "13.0.93.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "14", test_version2: "14.0.22.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "15", test_version2: "15.0.19.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

