CPE = "cpe:/a:cybozu:garoon";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813267" );
	script_version( "2021-06-24T11:00:30+0000" );
	script_cve_id( "CVE-2018-0607" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-24 11:00:30 +0000 (Thu, 24 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-09-24 17:29:00 +0000 (Mon, 24 Sep 2018)" );
	script_tag( name: "creation_date", value: "2018-07-27 11:06:53 +0530 (Fri, 27 Jul 2018)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Cybozu Garoon Notification List SQL Injection Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Cybozu Garoon
  and is prone to sql injection vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an input validation
  error in 'Notification List'." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary SQL commands via unspecified vectors." );
	script_tag( name: "affected", value: "Cybozu Garoon versions 3.5.0 to 4.6.2" );
	script_tag( name: "solution", value: "Upgrade to the Cybozu Garoon version 4.2.3
  or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://jvn.jp/en/jp/JVN13415512/index.html" );
	script_xref( name: "URL", value: "https://kb.cybozu.support/article/33120" );
	script_xref( name: "URL", value: "https://manual.cybozu.co.jp/en/desktop/install/install.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_cybozu_products_detect.sc" );
	script_mandatory_keys( "CybozuGaroon/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!cyPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: cyPort, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "3.5.0", test_version2: "4.6.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "4.6.3 or later.", install_path: path );
	security_message( data: report, port: cyPort );
	exit( 0 );
}

