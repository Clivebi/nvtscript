if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108158" );
	script_version( "2021-09-14T14:01:45+0000" );
	script_cve_id( "CVE-2016-4889" );
	script_bugtraq_id( 93215 );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-14 14:01:45 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-05-13 01:29:00 +0000 (Sat, 13 May 2017)" );
	script_tag( name: "creation_date", value: "2017-05-12 09:37:58 +0200 (Fri, 12 May 2017)" );
	script_name( "ManageEngine ServiceDesk Plus < 9.0 Access Bypass Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_manageengine_servicedesk_plus_consolidation.sc" );
	script_mandatory_keys( "manageengine/servicedesk_plus/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/93215" );
	script_xref( name: "URL", value: "https://www.manageengine.com/products/service-desk/readme-9.0.html" );
	script_tag( name: "summary", value: "This host is installed with ManageEngine ServiceDesk Plus and
  is prone to an access bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote authenticated guest user
  to have unspecified impact by leveraging failure to restrict access to unknown functions." );
	script_tag( name: "affected", value: "ManageEngine ServiceDesk Plus version prior to 9.0." );
	script_tag( name: "solution", value: "Upgrade to ManageEngine ServiceDesk Plus 9.0 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
CPE = "cpe:/a:zohocorp:manageengine_servicedesk_plus";
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
path = infos["location"];
if(version_is_less( version: version, test_version: "9.0b9000" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.0 (Build 9000)", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

