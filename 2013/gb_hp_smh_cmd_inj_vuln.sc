CPE = "cpe:/a:hp:system_management_homepage";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803846" );
	script_version( "2020-04-21T11:03:03+0000" );
	script_cve_id( "CVE-2013-3576" );
	script_bugtraq_id( 60471 );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-04-21 11:03:03 +0000 (Tue, 21 Apr 2020)" );
	script_tag( name: "creation_date", value: "2013-07-30 13:30:42 +0530 (Tue, 30 Jul 2013)" );
	script_name( "HP System Management Homepage Command Injection Vulnerability-July2013" );
	script_tag( name: "summary", value: "This host is running HP System Management Homepage (SMH) and is prone to
command injection  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Upgrade to version 7.2.2, or later." );
	script_xref( name: "URL", value: "http://h18013.www1.hp.com/products/servers/management/agents/index.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "insight", value: "The flaw is triggered when the ginkgosnmp.inc script uses the last path
segment of the current requested URL path in an exec call without properly
sanitizing the content." );
	script_tag( name: "affected", value: "HP System Management Homepage (SMH) version 7.2.1.3 and prior" );
	script_tag( name: "impact", value: "Successful exploitation will allow an authenticated remote attacker to execute
arbitrary commands." );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/26420" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/735364" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_hp_smh_detect.sc" );
	script_mandatory_keys( "HP/SMH/installed" );
	script_require_ports( "Services/www", 2381 );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "7.2.1.3" )){
	report = report_fixed_ver( installed_version: version, vulnerable_range: "Less than or equal to 7.2.1.3" );
	security_message( port: port, data: report );
	exit( 0 );
}

