CPE = "cpe:/a:ibm:tivoli_endpoint_manager";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809397" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2012-1837" );
	script_bugtraq_id( 78246 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-11-15 13:41:38 +0100 (Tue, 15 Nov 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "IBM Tivoli Endpoint Manager 'HTTPOnly flag' Information Disclosure Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with IBM Tivoli
  Endpoint Manager and is prone to information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to the webreports,
  post/create-role, and post/update-role programs do not include the HTTPOnly
  flag in a Set-Cookie header for a cookie." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to obtain potentially sensitive information." );
	script_tag( name: "affected", value: "IBM Tivoli Endpoint Manager versions
  before 8.2." );
	script_tag( name: "solution", value: "Upgrade to IBM Tivoli Endpoint Manager
  version 8.2. or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://infosec.cert-pa.it/cve-2012-1837.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_ibm_endpoint_manager_web_detect.sc" );
	script_mandatory_keys( "ibm_endpoint_manager/installed" );
	script_require_ports( "Services/www", 52311 );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!tivPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!tivVer = get_app_version( cpe: CPE, port: tivPort )){
	exit( 0 );
}
if(version_is_less( version: tivVer, test_version: "8.2" )){
	report = report_fixed_ver( installed_version: tivVer, fixed_version: "8.2" );
	security_message( port: tivPort, data: report );
	exit( 0 );
}

