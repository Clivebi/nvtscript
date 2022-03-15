CPE = "cpe:/a:hp:system_management_homepage";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804415" );
	script_version( "2020-04-20T13:31:49+0000" );
	script_cve_id( "CVE-2013-4846" );
	script_bugtraq_id( 66129 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-04-20 13:31:49 +0000 (Mon, 20 Apr 2020)" );
	script_tag( name: "creation_date", value: "2014-03-19 13:14:25 +0530 (Wed, 19 Mar 2014)" );
	script_name( "HP System Management Homepage Information Disclosure Vulnerability" );
	script_tag( name: "summary", value: "This host is running HP System Management Homepage (SMH) and is prone to
  information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An unspecified error can be exploited to disclose certain information. No further
  information is currently available." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to disclose certain information." );
	script_tag( name: "affected", value: "HP System Management Homepage (SMH) version before 7.3." );
	script_tag( name: "solution", value: "Upgrade to HP System Management Homepage (SMH) 7.3 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/57365" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2014/Mar/61" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_hp_smh_detect.sc" );
	script_mandatory_keys( "HP/SMH/installed" );
	script_require_ports( "Services/www", 2381 );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!smhPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!smhVer = get_app_version( cpe: CPE, port: smhPort )){
	exit( 0 );
}
if(version_is_less( version: smhVer, test_version: "7.3" )){
	report = report_fixed_ver( installed_version: smhVer, fixed_version: "7.3" );
	security_message( port: smhPort, data: report );
	exit( 0 );
}

