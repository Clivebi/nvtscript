CPE = "cpe:/a:opsview:opsview";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805663" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2015-4420" );
	script_bugtraq_id( 75223 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2015-06-23 19:01:29 +0530 (Tue, 23 Jun 2015)" );
	script_name( "Opsview Multiple Cross Site Scripting Vulnerabilities - June15" );
	script_tag( name: "summary", value: "This host is installed with Opsview and is prone to multiple cross site
scripting vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to improper validation of user input to
state/service /user/admin." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote to execute arbitrary code." );
	script_tag( name: "affected", value: "Opsview version 4.6.2 and earlier" );
	script_tag( name: "solution", value: "No known solution was made available
  for at least one year since the disclosure of this vulnerability. Likely none
  will be provided anymore. General solution options are to upgrade to a
  newer release, disable respective features, remove the product or replace
  the product by another one." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/37271/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_opsview_monitor_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "opsview_monitor/installed" );
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
if(version_is_less_equal( version: version, test_version: "4.6.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

