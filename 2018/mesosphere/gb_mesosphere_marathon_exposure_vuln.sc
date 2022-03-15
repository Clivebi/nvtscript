if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114012" );
	script_version( "2021-09-29T05:25:13+0000" );
	script_tag( name: "last_modification", value: "2021-09-29 05:25:13 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "creation_date", value: "2018-07-20 11:40:39 +0200 (Fri, 20 Jul 2018)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:P/A:P" );
	script_name( "Mesosphere Marathon Web UI Public WAN (Internet) / Public LAN Accessible" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "global_settings.sc", "gb_mesosphere_marathon_detect.sc" );
	script_mandatory_keys( "mesosphere/marathon/detected", "keys/is_public_addr" );
	script_xref( name: "URL", value: "https://info.lacework.com/hubfs/Containers%20At-Risk_%20A%20Review%20of%2021%2C000%20Cloud%20Environments.pdf" );
	script_tag( name: "summary", value: "The script checks if the Mesosphere Marathon Web UI is
  accessible from a public WAN (Internet) / public LAN." );
	script_tag( name: "insight", value: "The installation or configuration of Mesosphere Marathon might
  be incomplete and therefore unprotected and exposed to the public." );
	script_tag( name: "vuldetect", value: "Checks if the Mesosphere Marathon UI is accessible from a
  public WAN (Internet) / public LAN.

  Note: A configuration option 'Network type' to define if a scanned network should be seen as a
  public LAN can be found in the preferences of the following VT:

  Global variable settings (OID: 1.3.6.1.4.1.25623.1.0.12288)" );
	script_tag( name: "impact", value: "Access to the dashboard gives you top level access to all aspects
  of administration for the cluster it is assigned to manage. That includes managing applications,
  containers, starting workloads, adding and modifying applications, and setting key security
  controls." );
	script_tag( name: "solution", value: "It is highly recommended to consider the following:

  - Regardless of network policy, use MFA for all access.

  - Apply strict controls to network access, especially for UI and API ports.

  - Use SSL/TLS for all servers and use valid certificates with proper expiration and enforcement
  policies.

  - Investigate VPN (bastion), reverse proxy or direct connect connections to sensitive servers.

  - Look into product and services such as Lacework in order to discover, detect, prevent, and
  secure your container services." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("network_func.inc.sc");
require("host_details.inc.sc");
if(!is_public_addr()){
	exit( 0 );
}
CPE = "cpe:/a:mesosphere:marathon";
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port, nofork: TRUE )){
	exit( 0 );
}
if(get_kb_item( "mesosphere/marathon/" + port + "/detected" )){
	report = "Mesosphere Marathon UI is exposed to the public under the following URL: " + http_report_vuln_url( port: port, url: "/", url_only: TRUE );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

