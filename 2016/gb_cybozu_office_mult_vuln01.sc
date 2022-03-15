CPE = "cpe:/a:cybozu:office";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807276" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2016-1153", "CVE-2016-1152", "CVE-2016-1151", "CVE-2015-8489", "CVE-2015-8486", "CVE-2015-8485", "CVE-2015-8484" );
	script_bugtraq_id( 83288, 83287, 83284 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-03-03 18:23:55 +0530 (Thu, 03 Mar 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Cybozu Office Multiple Vulnerabilities-01 Feb16" );
	script_tag( name: "summary", value: "The host is installed with Cybozu Office
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error in 'customapp' function.

  - An error in multiple functions." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause a denial-of-service, view the information about the
  groupware, obtain privileged information or cause specific functions to
  become unusable." );
	script_tag( name: "affected", value: "Cybozu Office version 9.9.0 to 10.3.0" );
	script_tag( name: "solution", value: "Upgrade to Cybozu Office version 10.4.0
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://jvn.jp/en/jp/JVN20246313/index.html" );
	script_xref( name: "URL", value: "http://jvn.jp/en/jp/JVN48720230/index.html" );
	script_xref( name: "URL", value: "http://jvn.jp/en/jp/JVN64209269/index.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_cybozu_products_detect.sc" );
	script_mandatory_keys( "CybozuOffice/Installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!cybPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!cybVer = get_app_version( cpe: CPE, port: cybPort )){
	exit( 0 );
}
if(version_in_range( version: cybVer, test_version: "9.9.0", test_version2: "10.3.0" )){
	report = report_fixed_ver( installed_version: cybVer, fixed_version: "10.4.0" );
	security_message( data: report, port: cybPort );
	exit( 0 );
}
exit( 99 );

