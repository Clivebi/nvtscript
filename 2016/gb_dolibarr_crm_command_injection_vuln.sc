CPE = "cpe:/a:dolibarr:dolibarr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807851" );
	script_version( "2020-03-04T09:29:37+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-03-04 09:29:37 +0000 (Wed, 04 Mar 2020)" );
	script_tag( name: "creation_date", value: "2016-06-30 11:22:02 +0530 (Thu, 30 Jun 2016)" );
	script_name( "Dolibarr CRM Command Injection Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Dolibarr CRM
  and is prone to command injection vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due as Dolibarr is open to
  command injection via the backup tool available." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary commands on the affected system." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "affected", value: "Dolibarr CRM versions less than 3.9.1" );
	script_tag( name: "solution", value: "Upgrade to Dolibarr CRM version 3.9.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/137607" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dolibarr_detect.sc" );
	script_mandatory_keys( "dolibarr/detected" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "https://www.dolibarr.org" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!dolPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dolVer = get_app_version( cpe: CPE, port: dolPort )){
	exit( 0 );
}
if(version_is_less( version: dolVer, test_version: "3.9.1" )){
	report = report_fixed_ver( installed_version: dolVer, fixed_version: "3.9.1" );
	security_message( data: report, port: dolPort );
	exit( 0 );
}
exit( 99 );

