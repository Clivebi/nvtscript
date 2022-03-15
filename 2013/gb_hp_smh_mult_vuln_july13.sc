CPE = "cpe:/a:hp:system_management_homepage";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803845" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2012-5217", "CVE-2013-2355", "CVE-2013-2356", "CVE-2013-2357", "CVE-2013-2358", "CVE-2013-2359", "CVE-2013-2360", "CVE-2013-2361", "CVE-2013-2362", "CVE-2013-2363", "CVE-2013-2364", "CVE-2013-4821" );
	script_bugtraq_id( 61340, 61338, 61333, 61332, 61339, 61342, 61343, 61336, 61337, 61335, 61341 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-07-30 11:22:25 +0530 (Tue, 30 Jul 2013)" );
	script_name( "HP System Management Homepage Multiple Vulnerabilities-July2013" );
	script_tag( name: "summary", value: "This host is running HP System Management Homepage (SMH) and is prone to
multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Upgrade to version 7.2.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "insight", value: "Multiple unspecified errors exist and certain unspecified input is not
properly sanitised before being returned to the user." );
	script_tag( name: "affected", value: "HP System Management Homepage (SMH) version before 7.2.1" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to gain elevated privileges,
disclose sensitive information, perform unauthorized actions, or cause
denial of service conditions." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/54245" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2013/Jul/128" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2013/Jul/135" );
	script_xref( name: "URL", value: "http://h20565.www2.hp.com/portal/site/hpsc/template.PAGE/public/kb/docDisplay/?docId=emr_na-c03839862-1" );
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
if(version_is_less( version: version, test_version: "7.2.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.2.1" );
	security_message( port: port, data: report );
	exit( 0 );
}

