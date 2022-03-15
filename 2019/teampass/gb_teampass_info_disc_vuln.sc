if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112509" );
	script_version( "2021-09-06T11:01:35+0000" );
	script_cve_id( "CVE-2019-1000001" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-06 11:01:35 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-02-06 14:11:00 +0100 (Wed, 06 Feb 2019)" );
	script_name( "TeamPass <= 2.1.27 Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_teampass_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "teampass/installed" );
	script_tag( name: "summary", value: "TeamPass contains a storing passwords in a recoverable format vulnerability
  in shared password vaults that can result in all shared passwords being recoverable via the server side." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker that bypassed authentication
  to have access to all shared passwords a registered user has access to." );
	script_tag( name: "affected", value: "TeamPass through version 2.1.27." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "https://github.com/nilsteampassnet/TeamPass/issues/2495" );
	exit( 0 );
}
CPE = "cpe:/a:teampass:teampass";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less_equal( version: vers, test_version: "2.1.27" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "None" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

