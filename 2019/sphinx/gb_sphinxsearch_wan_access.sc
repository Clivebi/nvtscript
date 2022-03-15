CPE = "cpe:/a:sphinxsearch:sphinxsearch";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108621" );
	script_version( "2021-09-29T05:25:13+0000" );
	script_tag( name: "last_modification", value: "2021-09-29 05:25:13 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-08-27 08:54:09 +0000 (Tue, 27 Aug 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Sphinx Search Server Public WAN (Internet) / Public LAN Accessible" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "sw_sphinxsearch_detect.sc", "global_settings.sc" );
	script_mandatory_keys( "sphinxsearch/noauth", "keys/is_public_addr" );
	script_xref( name: "URL", value: "https://www.bsi.bund.de/EN/Topics/IT-Crisis-Management/CERT-Bund/CERT-Reports/HOWTOs/Open-Sphinx-Server/open-Sphinx-server_node.html" );
	script_tag( name: "summary", value: "The script checks if the target host is running an Sphinx search
  server accessible from a public WAN (Internet) / public LAN." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration." );
	script_tag( name: "vuldetect", value: "Evaluate if the target host is running an Sphinx search server
  accessible from a public WAN (Internet) / public LAN.

  Note: A configuration option 'Network type' to define if a scanned network should be seen as a
  public LAN can be found in the preferences of the following VT:

  Global variable settings (OID: 1.3.6.1.4.1.25623.1.0.12288)" );
	script_tag( name: "solution", value: "Only allow access to the Sphinx search server from trusted
  sources." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("host_details.inc.sc");
require("network_func.inc.sc");
if(!is_public_addr()){
	exit( 0 );
}
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(!get_kb_item( "sphinxsearch/" + port + "/noauth" )){
	exit( 99 );
}
security_message( port: port );
exit( 0 );

