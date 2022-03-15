CPE = "cpe:/a:apache:couchdb";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813909" );
	script_version( "2021-06-14T11:00:34+0000" );
	script_cve_id( "CVE-2018-11769" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-14 11:00:34 +0000 (Mon, 14 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-08-09 17:22:53 +0530 (Thu, 09 Aug 2018)" );
	script_name( "Apache CouchDB 'HTTP API' Privilege Escalation Vulnerability Aug18 (Linux)" );
	script_tag( name: "summary", value: "This host is installed with Apache CouchDB
  and is prone to privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an insufficient
  validation of administrator-supplied configuration settings via the HTTP
  API." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attackers to escalate their privileges to that of the operating system's
  and remotely execute arbitrary code." );
	script_tag( name: "affected", value: "Apache CouchDB versions before 2.2.0 on Linux." );
	script_tag( name: "solution", value: "Upgrade to Apache CouchDB version 2.2.0
  or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "https://lists.apache.org/thread.html/1052ad7a1b32b9756df4f7860f5cb5a96b739f444117325a19a4bf75@%3Cdev.couchdb.apache.org%3E" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_couchdb_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 5984 );
	script_mandatory_keys( "couchdb/installed", "Host/runs_unixoide" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!cPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: cPort, exit_no_version: TRUE )){
	exit( 0 );
}
cVer = infos["version"];
cPath = infos["location"];
if(version_is_less( version: cVer, test_version: "2.2.0" )){
	report = report_fixed_ver( installed_version: cVer, fixed_version: "2.2.0", install_path: cPath );
	security_message( port: cPort, data: report );
	exit( 0 );
}

