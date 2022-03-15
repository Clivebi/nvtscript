CPE = "cpe:/a:monstra:monstra";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117541" );
	script_version( "2021-07-08T09:33:39+0000" );
	script_tag( name: "last_modification", value: "2021-07-08 09:33:39 +0000 (Thu, 08 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-08 09:26:13 +0000 (Thu, 08 Jul 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Monstra CMS End of Life (EOL) Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_monstra_cms_detect.sc" );
	script_mandatory_keys( "monstra_cms/detected" );
	script_xref( name: "URL", value: "https://github.com/monstra-cms/monstra/issues/460" );
	script_tag( name: "summary", value: "The remote host is using Monstra CMS which is discontinued and
  will not receive any security updates." );
	script_tag( name: "vuldetect", value: "Checks if the target host is using a discontinued product." );
	script_tag( name: "impact", value: "A discontinued product is not receiving any security updates from
  the vendor. Unfixed security vulnerabilities might be leveraged by an attacker to compromise the
  security of this host." );
	script_tag( name: "solution", value: "Replace Monstra CMS with Flextype which is still supported by
  the vendor." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("host_details.inc.sc");
require("misc_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!loc = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
report = build_eol_message( name: "Monstra CMS", cpe: CPE, location: loc, skip_version: TRUE, eol_version: "All versions", eol_date: "2018-11-22", eol_url: "https://github.com/monstra-cms/monstra/issues/460", eol_type: "prod" );
security_message( port: port, data: report );
exit( 0 );

