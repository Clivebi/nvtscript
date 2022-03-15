CPE = "cpe:/a:hp:system_management_homepage";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902257" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-09-29 09:26:02 +0200 (Wed, 29 Sep 2010)" );
	script_cve_id( "CVE-2010-3284", "CVE-2010-3283" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_name( "HP System Management Homepage Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "secpod_hp_smh_detect.sc" );
	script_mandatory_keys( "HP/SMH/installed" );
	script_require_ports( "Services/www", 2301, 2381 );
	script_xref( name: "URL", value: "http://marc.info/?l=bugtraq&m=128525531721328&w=2" );
	script_xref( name: "URL", value: "http://marc.info/?l=bugtraq&m=128525419119241&w=2" );
	script_xref( name: "URL", value: "http://h18000.www1.hp.com/products/servers/management/agents/index.html" );
	script_tag( name: "insight", value: "The flaws are due to:

  - An unspecified error in the application, allows remote attackers to
  obtain sensitive information via unknown vectors.

  - An open redirect vulnerability in the application, allows remote
  attackers to redirect users to arbitrary web sites and conduct phishing
  attacks via unspecified vectors." );
	script_tag( name: "solution", value: "Upgrade to HP System Management Homepage 6.2 or later." );
	script_tag( name: "summary", value: "This host is running HP System Management Homepage (SMH) and is
  prone to multiple vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to obtain sensitive information
  or to redirect users to arbitrary web sites and conduct phishing attacks." );
	script_tag( name: "affected", value: "HP System Management Homepage versions prior to 6.2 on all platforms." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "6.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.2" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

