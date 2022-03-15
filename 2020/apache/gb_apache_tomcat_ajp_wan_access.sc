if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108716" );
	script_version( "2021-09-29T05:25:13+0000" );
	script_tag( name: "last_modification", value: "2021-09-29 05:25:13 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "creation_date", value: "2020-03-02 11:09:59 +0000 (Mon, 02 Mar 2020)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Apache JServ Protocol (AJP) Public WAN (Internet) / Public LAN Accessible" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_jserv_ajp_detect.sc", "global_settings.sc" );
	script_require_ports( "Services/ajp13", 8009 );
	script_mandatory_keys( "apache/ajp/detected", "keys/is_public_addr" );
	script_xref( name: "URL", value: "https://lists.apache.org/thread.html/r7c6f492fbd39af34a68681dbbba0468490ff1a97a1bd79c6a53610ef%40%3Cannounce.tomcat.apache.org%3E" );
	script_tag( name: "summary", value: "The script checks if the target host is running a service
  supporting the Apache JServ Protocol (AJP) accessible from a public WAN (Internet) / public LAN." );
	script_tag( name: "insight", value: "When using the Apache JServ Protocol (AJP), care must be taken
  when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having
  higher trust than, for example, a similar HTTP connection. If such connections are available to an
  attacker, they can be exploited in ways that may be surprising (e.g. bypassing security checks,
  bypassing user authentication among others)." );
	script_tag( name: "vuldetect", value: "Evaluate if the target host is running a service supporting
  the Apache JServ Protocol (AJP) accessible from a public WAN (Internet) / public LAN.

  Note: A configuration option 'Network type' to define if a scanned network should be seen as a
  public LAN can be found in the preferences of the following VT:

  Global variable settings (OID: 1.3.6.1.4.1.25623.1.0.12288)" );
	script_tag( name: "solution", value: "Only allow access to the AJP service from trusted sources /
  networks." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("network_func.inc.sc");
if(!is_public_addr()){
	exit( 0 );
}
port = service_get_port( default: 8009, proto: "ajp13" );
if(!get_kb_item( "apache/ajp/" + port + "/detected" )){
	exit( 99 );
}
security_message( port: port );
exit( 0 );

