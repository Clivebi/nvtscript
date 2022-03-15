if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802531" );
	script_version( "2019-12-18T15:04:04+0000" );
	script_cve_id( "CVE-2008-0346" );
	script_bugtraq_id( 27229 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-12-18 15:04:04 +0000 (Wed, 18 Dec 2019)" );
	script_tag( name: "creation_date", value: "2011-12-07 13:09:22 +0530 (Wed, 07 Dec 2011)" );
	script_name( "Oracle Application Server Unspecified Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_oracle_app_server_detect.sc" );
	script_mandatory_keys( "oracle/application_server/detected" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1019218" );
	script_tag( name: "impact", value: "An unspecified impact and attack vectors." );
	script_tag( name: "affected", value: "Oracle application server version 1.3.1.27." );
	script_tag( name: "insight", value: "The flaw is due to unspecified error in the oracle jinitiator
  component." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "summary", value: "This host is running Oracle application server and is prone to
  unspecified vulnerability." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
CPE = "cpe:/a:oracle:application_server";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "1.3.1.27" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.3.1.27" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

