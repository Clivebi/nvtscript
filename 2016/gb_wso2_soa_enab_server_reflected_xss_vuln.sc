CPE = "cpe:/a:wso2:enablement_server_for_java";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808052" );
	script_version( "2021-09-20T08:01:57+0000" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-20 08:01:57 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-09 20:00:00 +0000 (Tue, 09 Oct 2018)" );
	script_tag( name: "creation_date", value: "2016-05-20 12:11:56 +0530 (Fri, 20 May 2016)" );
	script_name( "WSO2 SOA Enablement Server Reflected Cross-Site Scripting Vulnerability" );
	script_cve_id( "CVE-2016-4327" );
	script_tag( name: "summary", value: "The host is running WSO2 SOA Enablement
  Server and is prone to reflected cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Cross-site scripting (XSS) vulnerability in WSO2 SOA Enablement Server
allows remote attackers to inject arbitrary web script or HTML via the PATH_INFO." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to obtain potentially sensitive information, which may lead to
  further attacks." );
	script_tag( name: "affected", value: "WSO2 SOA Enablement Server for Java/6.6 build
  SSJ-6.6-20090827-1616 and earlier." );
	script_tag( name: "solution", value: "Contact the vendor for a patch." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/538413" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wso2_soa_enab_server_detect.sc" );
	script_mandatory_keys( "WSO2/SOA/Enablement_Server/Installed" );
	script_require_ports( "Services/www", 8080 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!wsoPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: wsoPort )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "6.6-20090827-1616" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "Contact Vendor" );
	security_message( port: wsoPort, data: report );
	exit( 0 );
}
exit( 0 );

