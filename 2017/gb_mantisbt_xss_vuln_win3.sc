CPE = "cpe:/a:mantisbt:mantisbt";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108103" );
	script_version( "2021-09-16T14:01:49+0000" );
	script_cve_id( "CVE-2017-7222" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-16 14:01:49 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-03-23 13:55:00 +0000 (Thu, 23 Mar 2017)" );
	script_tag( name: "creation_date", value: "2017-03-23 09:57:33 +0100 (Thu, 23 Mar 2017)" );
	script_name( "MantisBT 'view_type' Cross Site Scripting Vulnerability (Windows)" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "mantis_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "mantisbt/detected", "Host/runs_windows" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "https://mantisbt.org/bugs/view.php?id=22266" );
	script_tag( name: "summary", value: "This host is installed with MantisBT
  and is prone to a cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Successfully exploitation will allow remote
  attacker to execute arbitrary script code in the browser of an unsuspecting user
  in the context of the affected site. This may allow the attacker to steal
  cookie-based authentication credentials and to launch other attacks." );
	script_tag( name: "affected", value: "MantisBT versions versions before 2.1.1." );
	script_tag( name: "solution", value: "Update to MantisBT 2.1.1 or higher." );
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
if(version_is_less( version: vers, test_version: "2.1.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.1.1" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

