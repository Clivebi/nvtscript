CPE = "cpe:/a:mantisbt:mantisbt";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812755" );
	script_version( "2021-06-25T02:00:34+0000" );
	script_cve_id( "CVE-2018-6526" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-25 02:00:34 +0000 (Fri, 25 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-04-08 01:29:00 +0000 (Sun, 08 Apr 2018)" );
	script_tag( name: "creation_date", value: "2018-02-05 11:55:27 +0530 (Mon, 05 Feb 2018)" );
	script_name( "MantisBT 'view_all_bug_page' Path Disclosure Vulnerability (Windows)" );
	script_tag( name: "summary", value: "This host is installed with MantisBT and is
  prone to a path disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to insufficient validation
  of user supplied input via 'filter' parameter related to a 'filter_ensure_valid_filter'
  call in 'current_user_api.php' script." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause site path leakage." );
	script_tag( name: "affected", value: "MantisBT version 2.10.0 on Windows" );
	script_tag( name: "solution", value: "Upgrade to MantisBT version 2.11.0 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://mantisbt.org/bugs/view.php?id=23921" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "mantis_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "mantisbt/detected", "Host/runs_windows" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "http://www.mantisbt.org/download.php" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!manPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: manPort, exit_no_version: TRUE )){
	exit( 0 );
}
manVer = infos["version"];
path = infos["location"];
if(manVer == "2.10.0"){
	report = report_fixed_ver( installed_version: manVer, fixed_version: "2.11.0", install_path: path );
	security_message( port: manPort, data: report );
	exit( 0 );
}
exit( 0 );

