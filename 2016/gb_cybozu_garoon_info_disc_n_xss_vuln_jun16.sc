CPE = "cpe:/a:cybozu:garoon";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807850" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-7776", "CVE-2015-7775" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-06-30 09:39:45 +0530 (Thu, 30 Jun 2016)" );
	script_name( "Cybozu Garoon Information Disclosure And Cross-Site Scripting Vulnerabilities - Jun16" );
	script_tag( name: "summary", value: "This host is installed with cybozu garoon
  and is vulnerable to information disclosure and cross-site scripting
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - The application does not properly restrict loading of IMG elements.

  - An insufficient validation of input passed to unspecified vectors." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML code and gain access to
  potentially sensitive information." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "affected", value: "Cybozu Garoon versions 3.x and 4.x before
  4.2.0" );
	script_tag( name: "solution", value: "Upgrade to Cybozu Garoon 4.2.0 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.cybozu.com/ja-jp/article/8757" );
	script_xref( name: "URL", value: "https://support.cybozu.com/ja-jp/article/8897" );
	script_xref( name: "URL", value: "https://support.cybozu.com/ja-jp/article/8951" );
	script_xref( name: "URL", value: "https://support.cybozu.com/ja-jp/article/8982" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_cybozu_products_detect.sc" );
	script_mandatory_keys( "CybozuGaroon/Installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "https://garoon.cybozu.co.jp" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!cyPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!cyVer = get_app_version( cpe: CPE, port: cyPort )){
	exit( 0 );
}
if(version_in_range( version: cyVer, test_version: "3.0", test_version2: "4.0.3" )){
	report = report_fixed_ver( installed_version: cyVer, fixed_version: "4.2.0" );
	security_message( data: report, port: cyPort );
	exit( 0 );
}

