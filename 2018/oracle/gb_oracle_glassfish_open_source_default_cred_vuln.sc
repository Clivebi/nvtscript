CPE = "cpe:/a:oracle:glassfish_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813576" );
	script_version( "2021-06-30T02:00:35+0000" );
	script_cve_id( "CVE-2018-14324" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-30 02:00:35 +0000 (Wed, 30 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-20 21:29:00 +0000 (Mon, 20 May 2019)" );
	script_tag( name: "creation_date", value: "2018-07-17 12:45:41 +0530 (Tue, 17 Jul 2018)" );
	script_name( "Oracle GlassFish Open Source Default Credentials Vulnerability" );
	script_tag( name: "summary", value: "This host is running Oracle GlassFish Server
  and is prone to a default credentials vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to the demo feature in Oracle
  GlassFish Open Source Edition having TCP port 7676 open by default with a password
  of admin for the admin account." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to obtain potentially sensitive information, perform database operations, or
  manipulate the demo via a JMX RMI session." );
	script_tag( name: "affected", value: "Oracle GlassFish Server versions 5.0." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://www.securitytracker.com/id/1041292" );
	script_xref( name: "URL", value: "https://github.com/eclipse-ee4j/glassfish/issues/22500" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "GlassFish_detect.sc" );
	script_mandatory_keys( "GlassFish/installed" );
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
if(version_is_equal( version: version, test_version: "5.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

