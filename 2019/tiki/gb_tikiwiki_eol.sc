CPE = "cpe:/a:tiki:tikiwiki_cms/groupware";
EOL_URL = "https://tiki.org/Versions#Version_Lifecycle";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108622" );
	script_version( "2020-12-09T14:13:00+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-12-09 14:13:00 +0000 (Wed, 09 Dec 2020)" );
	script_tag( name: "creation_date", value: "2019-08-27 09:44:15 +0000 (Tue, 27 Aug 2019)" );
	script_name( "Tiki Wiki CMS Groupware End of Life (EOL) Detection" );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_tikiwiki_detect.sc" );
	script_mandatory_keys( "TikiWiki/installed" );
	script_xref( name: "URL", value: "https://tiki.org/Versions#Version_Lifecycle" );
	script_tag( name: "summary", value: "The Tiki Wiki CMS Groupware version on the remote host has reached
  the End of Life (EOL) and should not be used anymore." );
	script_tag( name: "impact", value: "An EOL version of Tiki Wiki CMS Groupware is not receiving any
  security updates from the vendor. Unfixed security vulnerabilities might be leveraged by an attacker to
  compromise the security of this host." );
	script_tag( name: "solution", value: "Update the Tiki Wiki CMS Groupware version on the remote host to a
  still supported version." );
	script_tag( name: "vuldetect", value: "Checks if an EOL version is present on the target host." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("products_eol.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
if(ret = product_reached_eol( cpe: CPE, version: vers )){
	path = infos["location"];
	report = build_eol_message( name: "Tiki Wiki CMS Groupware", cpe: CPE, version: vers, location: http_report_vuln_url( port: port, url: path, url_only: TRUE ), eol_version: ret["eol_version"], eol_date: ret["eol_date"], eol_type: "prod", eol_url: EOL_URL );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

