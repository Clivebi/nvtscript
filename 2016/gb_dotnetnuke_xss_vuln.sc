CPE = "cpe:/a:dotnetnuke:dotnetnuke";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809281" );
	script_version( "2020-03-04T09:29:37+0000" );
	script_cve_id( "CVE-2016-7119" );
	script_bugtraq_id( 92719 );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-03-04 09:29:37 +0000 (Wed, 04 Mar 2020)" );
	script_tag( name: "creation_date", value: "2016-09-22 12:36:34 +0530 (Thu, 22 Sep 2016)" );
	script_name( "DotNetNuke (DNN) Cross Site Scripting Vulnerability" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dotnetnuke_detect.sc" );
	script_mandatory_keys( "dotnetnuke/installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "http://www.dnnsoftware.com/community/security/security-center" );
	script_tag( name: "summary", value: "This host is installed with DotNetNuke
  and is prone to cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to improper handling
  of user-profile biography section." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  authenticated users to inject arbitrary web script." );
	script_tag( name: "affected", value: "DotNetNuke (DNN) versions before 8.0.1." );
	script_tag( name: "solution", value: "Upgrade to DotNetNuke 8.0.1 or later." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!dnnPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dnnVer = get_app_version( cpe: CPE, port: dnnPort )){
	exit( 0 );
}
if(version_is_less( version: dnnVer, test_version: "8.0.1" )){
	report = report_fixed_ver( installed_version: dnnVer, fixed_version: "8.0.1" );
	security_message( data: report, port: dnnPort );
}
exit( 0 );

