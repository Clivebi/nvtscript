CPE = "cpe:/a:cybozu:garoon";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107165" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-05-11 11:54:29 +0200 (Thu, 11 May 2017)" );
	script_cve_id( "CVE-2016-1213", "CVE-2016-1214", "CVE-2016-1215", "CVE-2016-1216", "CVE-2016-1217", "CVE-2016-1218", "CVE-2016-1219", "CVE-2016-1220" );
	script_bugtraq_id( 92596, 92598, 92599, 92600, 92601 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-04-25 16:09:00 +0000 (Tue, 25 Apr 2017)" );
	script_name( "Cybozu Garoon Multiple Vulnerabilities - Aug16" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_cybozu_products_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "CybozuGaroon/Installed" );
	script_tag( name: "summary", value: "This host is installed with Cybozu Garoon
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to do redirection,
  XSS, authentication bypass, SQL injection and denial-of-services attacks." );
	script_tag( name: "affected", value: "Cybozu Garoon before version 4.2.2." );
	script_tag( name: "solution", value: "Update to Cybozu Garoon 4.2.2 or later." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/92599" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/92598" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/92600" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/92596" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/92601" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!ver = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: ver, test_version: "4.2.2" )){
	report = report_fixed_ver( installed_version: ver, fixed_version: "4.2.2" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

