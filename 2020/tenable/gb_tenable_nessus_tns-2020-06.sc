CPE = "cpe:/a:tenable:nessus";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112814" );
	script_version( "2021-07-13T02:01:14+0000" );
	script_tag( name: "last_modification", value: "2021-07-13 02:01:14 +0000 (Tue, 13 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-08-24 09:31:11 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "cvss_base", value: "3.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-28 18:53:00 +0000 (Fri, 28 Aug 2020)" );
	script_cve_id( "CVE-2020-5774" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Tenable Nessus < 8.11.1 Session Expiration Vulnerability (TNS-2020-06)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_nessus_web_server_detect.sc" );
	script_mandatory_keys( "nessus/installed" );
	script_tag( name: "summary", value: "Tenable Nessus is prone to a lack of proper session expiration." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Nessus was found to be maintaining sessions longer than the permitted period in certain scenarios." );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers with local access to login into an existing browser session." );
	script_tag( name: "affected", value: "Tenable Nessus version 8.11.0 and prior." );
	script_tag( name: "solution", value: "Update to version 8.11.1 or later." );
	script_xref( name: "URL", value: "https://www.tenable.com/security/tns-2020-06" );
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
if(version_is_less( version: version, test_version: "8.11.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.11.1", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

