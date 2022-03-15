CPE = "cpe:/a:webmin:webmin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811504" );
	script_version( "2021-09-30T08:43:52+0000" );
	script_cve_id( "CVE-2017-2106" );
	script_bugtraq_id( 96227 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-30 08:43:52 +0000 (Thu, 30 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-05-10 00:40:00 +0000 (Wed, 10 May 2017)" );
	script_tag( name: "creation_date", value: "2017-07-11 15:47:13 +0530 (Tue, 11 Jul 2017)" );
	script_name( "Webmin Multiple Unspecified XSS Vulnerabilities July17 (Linux)" );
	script_tag( name: "summary", value: "Webmin is prone to multiple unspecified cross site scripting vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to issues in
  outputting error messages into a HTML page and the function to edit the
  database." );
	script_tag( name: "impact", value: "Successful exploitation will lead an attacker
  to inject arbitrary web script or HTML." );
	script_tag( name: "affected", value: "Webmin versions before 1.830" );
	script_tag( name: "solution", value: "Upgrade to Webmin version 1.830 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://jvn.jp/en/jp/JVN34207650/index.html" );
	script_xref( name: "URL", value: "http://www.webmin.com/changes.html" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "webmin.sc", "os_detection.sc" );
	script_mandatory_keys( "webmin/installed", "Host/runs_unixoide" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!wmport = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!wmver = get_app_version( cpe: CPE, port: wmport )){
	exit( 0 );
}
if(version_is_less( version: wmver, test_version: "1.830" )){
	report = report_fixed_ver( installed_version: wmver, fixed_version: "1.830" );
	security_message( data: report, port: wmport );
	exit( 0 );
}
exit( 0 );

