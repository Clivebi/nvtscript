CPE = "cpe:/a:dell:emc_openmanage_server_administrator";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807564" );
	script_version( "2021-09-20T12:38:59+0000" );
	script_cve_id( "CVE-2016-4004" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-20 12:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-12-03 03:27:00 +0000 (Sat, 03 Dec 2016)" );
	script_tag( name: "creation_date", value: "2016-04-27 10:47:16 +0530 (Wed, 27 Apr 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Dell OpenManage Server Administrator Directory Traversal Vulnerability - April16" );
	script_tag( name: "summary", value: "Dell OpenManage Server Administrator is prone to a directory traversal
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to insufficient validation
  of user supplied input via 'file' parameter to ViewFile." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  authenticated administrators to read arbitrary files on the affected system." );
	script_tag( name: "affected", value: "Dell OpenManage Server Administrator
  version 8.4 and prior." );
	script_tag( name: "solution", value: "Update to version 8.5" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://vuldb.com/?id.82281" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/39486" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dell_omsa_remote_detect.sc" );
	script_mandatory_keys( "dell/openmanage_server_administrator/detected" );
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
if(version_is_less( version: version, test_version: "8.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.5", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

