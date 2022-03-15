CPE = "cpe:/a:greenbone:greenbone_security_assistant";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108196" );
	script_version( "2021-09-15T10:01:53+0000" );
	script_cve_id( "CVE-2016-1926" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-15 10:01:53 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-09 19:59:00 +0000 (Tue, 09 Oct 2018)" );
	script_tag( name: "creation_date", value: "2017-07-26 13:00:00 +0200 (Wed, 26 Jul 2017)" );
	script_name( "Greenbone Security Assistant 6.0 < 6.0.8 Cross-Site Scripting Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_gsa_detect.sc" );
	script_require_ports( "Services/www", 80, 443, 9392 );
	script_mandatory_keys( "greenbone_security_assistant/detected" );
	script_xref( name: "URL", value: "http://openvas.org/OVSA20160113.html" );
	script_tag( name: "summary", value: "It has been identified that Greenbone Security Assistant (GSA) is vulnerable to cross site scripting
  vulnerability." );
	script_tag( name: "insight", value: "The flaw exists due to an improper handling of the parameters of the get_aggregate command." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Given the attacker has access to a session token of the browser session, the cross site scripting
  can be executed." );
	script_tag( name: "affected", value: "Greenbone Security Assistant version 6.0.x before 6.0.8." );
	script_tag( name: "solution", value: "Update Greenbone Security Assistant to version 6.0.8 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "6.0.0", test_version2: "6.0.7" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "6.0.8" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

