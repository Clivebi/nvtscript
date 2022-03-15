CPE = "cpe:/a:icewarp:mail_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140331" );
	script_version( "2021-09-16T10:32:36+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 10:32:36 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-29 10:02:16 +0700 (Tue, 29 Aug 2017)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-08-29 14:36:00 +0000 (Tue, 29 Aug 2017)" );
	script_cve_id( "CVE-2017-12844" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "IceWarp <= 10.4.4 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_icewarp_consolidation.sc" );
	script_mandatory_keys( "icewarp/mailserver/http/detected" );
	script_tag( name: "summary", value: "IceWarp is prone to a cross-site scripting vulnerability" );
	script_tag( name: "insight", value: "Cross-site scripting (XSS) vulnerability in the admin panel in IceWarp Mail
  Server allows remote authenticated domain administrators to inject arbitrary web script or HTML via a crafted
  user name." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "IceWarp version 10.4.4 and maybe prior and later." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "https://youtu.be/MI4dhEia1d4" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "10.4.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "No information available" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

