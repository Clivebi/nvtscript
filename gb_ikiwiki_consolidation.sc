if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113158" );
	script_version( "$Revision: 11885 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2018-04-17 15:50:00 +0200 (Tue, 17 Apr 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "IkiWiki Detection Consolidation" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_ikiwiki_ssh_detect.sc", "gb_ikiwiki_webui_detect.sc" );
	script_mandatory_keys( "ikiwiki/detected" );
	script_tag( name: "summary", value: "Detection of IkiWiki.

  Collects detection results and consolidates them." );
	script_xref( name: "URL", value: "https://ikiwiki.info/" );
	exit( 0 );
}
CPE = "cpe:/a:ikiwiki:ikiwiki";
require("host_details.inc.sc");
require("cpe.inc.sc");
version_array = make_array();
if(webui_ports = get_kb_list( "ikiwiki/webui/port" )){
	for port in webui_ports {
		concluded = get_kb_item( "ikiwiki/webui/" + port + "/concluded" );
		location = get_kb_item( "ikiwiki/webui/" + port + "/location" );
		version = get_kb_item( "ikiwiki/webui/" + port + "/version" );
		register_product( cpe: CPE, location: location, port: port, service: "www" );
		if(isnull( version_array[version] )){
			version_array[version] = port + ":" + location + ":" + concluded;
		}
	}
}
if(ssh_ports = get_kb_list( "ikiwiki/ssh/port" )){
	for port in ssh_ports {
		concluded = get_kb_item( "ikiwiki/ssh/" + port + "/concluded" );
		location = get_kb_item( "ikiwiki/ssh/" + port + "/location" );
		version = get_kb_item( "ikiwiki/ssh/" + port + "/version" );
		register_product( cpe: CPE, location: location, port: port );
		if(isnull( version_array[version] )){
			version_array[version] = port + ":" + location + ":" + concluded;
		}
	}
}
for version in keys( version_array ) {
	infos = eregmatch( string: version_array[version], pattern: "([^:]*):([^:]*):([^:]*)" );
	if(!isnull( infos[1] )){
		port = infos[1];
	}
	if(!isnull( infos[2] )){
		location = infos[2];
	}
	if(!isnull( infos[3] )){
		concluded = infos[3];
	}
	register_and_report_cpe( app: "IkiWiki", ver: version, base: CPE + ":", expr: "([0-9.]+)", regPort: port, insloc: location, concluded: concluded );
}
exit( 0 );

