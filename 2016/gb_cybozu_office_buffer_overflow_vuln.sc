CPE = "cpe:/a:cybozu:office";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807280" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2014-5314" );
	script_bugtraq_id( 71057 );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-03-03 18:23:57 +0530 (Thu, 03 Mar 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Cybozu Office Buffer Overflow Vulnerability Feb16" );
	script_tag( name: "summary", value: "The host is installed with Cybozu Office
  and is prone to buffer overflow vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an unspecified
  buffer overflow vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause denial-of-service, or execute arbitrary code." );
	script_tag( name: "affected", value: "Cybozu Office version prior to 10.0.2" );
	script_tag( name: "solution", value: "Upgrade to Cybozu Office version 10.1.0
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://jvn.jp/en/jp/JVN14691234/index.html" );
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
if(version_is_less( version: cybVer, test_version: "10.0.3" )){
	report = report_fixed_ver( installed_version: cybVer, fixed_version: "10.1.0" );
	security_message( data: report, port: cybPort );
	exit( 0 );
}
exit( 99 );

