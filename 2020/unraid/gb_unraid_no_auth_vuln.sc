CPE = "cpe:/o:unraid:unraid";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143517" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2020-02-14 07:00:18 +0000 (Fri, 14 Feb 2020)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_name( "Unraid OS WebUI Missing Authentication" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_unraid_http_detect.sc" );
	script_mandatory_keys( "unraid/detected" );
	script_require_ports( "Services/www", 80, 443 );
	script_tag( name: "summary", value: "The script checks if the Web UI of Unraid OS is accessible without authentication." );
	script_tag( name: "vuldetect", value: "Checks if authentication is enabled." );
	script_tag( name: "impact", value: "An unauthenticated attacker might get full control over the host." );
	script_tag( name: "solution", value: "Enable authentication for the Web UI." );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(!get_kb_item( "unraid/http/" + port + "/noauth" )){
	exit( 99 );
}
url = get_kb_item( "unraid/http/" + port + "/noauth/checkedUrl" );
report = http_report_vuln_url( port: port, url: url );
security_message( port: port, data: report );
exit( 0 );

