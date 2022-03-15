CPE = "cpe:/a:mylittletools:mylittleadmin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144088" );
	script_version( "2021-08-16T12:00:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-16 12:00:57 +0000 (Mon, 16 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-06-09 03:59:10 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-22 21:15:00 +0000 (Fri, 22 May 2020)" );
	script_cve_id( "CVE-2020-13166" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "myLittleAdmin <= 3.8 RCE Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_mylittleadmin_http_detect.sc" );
	script_mandatory_keys( "mylittleadmin/detected" );
	script_tag( name: "summary", value: "myLittleAdmin is prone to an unauthenticated remote code
  execution (RCE) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The management tool in MyLittleAdmin allows remote attackers to
  execute arbitrary code because the machineKey is hardcoded (the same for all customers'
  installations) in web.config, and can be used to send serialized ASP code." );
	script_tag( name: "affected", value: "myLittleAdmin version 3.8 and probably prior." );
	script_tag( name: "solution", value: "No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one." );
	script_xref( name: "URL", value: "https://ssd-disclosure.com/ssd-advisory-mylittleadmin-preauth-rce/" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/157808/Plesk-myLittleAdmin-ViewState-.NET-Deserialization.html" );
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
if(version_is_less_equal( version: version, test_version: "3.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

