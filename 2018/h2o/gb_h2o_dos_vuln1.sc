CPE = "cpe:/a:h2o_project:h2o";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140822" );
	script_version( "2021-05-27T09:28:58+0000" );
	script_tag( name: "last_modification", value: "2021-05-27 09:28:58 +0000 (Thu, 27 May 2021)" );
	script_tag( name: "creation_date", value: "2018-02-27 16:25:17 +0700 (Tue, 27 Feb 2018)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-19 14:01:00 +0000 (Mon, 19 Apr 2021)" );
	script_cve_id( "CVE-2016-7835" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "H2O HTTP Server DoS Vulnerability-01" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_h2o_http_server_detect.sc" );
	script_mandatory_keys( "h2o/installed" );
	script_tag( name: "summary", value: "Use-after-free vulnerability in H2O allows remote attackers to cause a
denial-of-service (DoS) or obtain server certificate private keys and possibly other information." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "H2O version 2.0.4 and prior." );
	script_tag( name: "solution", value: "Update to version 2.0.5 or later." );
	script_xref( name: "URL", value: "https://github.com/h2o/h2o/issues/1144" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "2.0.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.0.5" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

