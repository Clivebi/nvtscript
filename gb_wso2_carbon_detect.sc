if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106178" );
	script_version( "2020-08-28T06:35:58+0000" );
	script_tag( name: "last_modification", value: "2020-08-28 06:35:58 +0000 (Fri, 28 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-10-10 12:16:07 +0700 (Mon, 10 Oct 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "WSO2 Carbon Products Detection" );
	script_tag( name: "summary", value: "Detection of WSO2 Carbon based Products

The script sends a connection request to the server and attempts to detect the presence of WSO2 Carbon based
products and the version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 9443 );
	script_mandatory_keys( "WSO2_Carbon/banner" );
	script_xref( name: "URL", value: "http://wso2.com/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 9443 );
banner = http_get_remote_headers( port: port );
if(ContainsString( banner, "Server: WSO2 Carbon Server" )){
	url = "/carbon/product/about.html";
	req = http_get( port: port, item: url );
	res = http_keepalive_send_recv( port: port, data: req );
	if(ContainsString( res, "<title>WSO2 " )){
		prod = eregmatch( pattern: "About WSO2 ([^<]+)", string: res );
		if(isnull( prod[1] )){
			exit( 0 );
		}
		prod = chomp( prod[1] );
		if( prod == "Identity Server" ){
			kb_name = "wso2_carbon_identity_server";
			cpe = "cpe:/a:wso2:identity_server";
			app = "WSO2 Identity Server";
		}
		else {
			if( prod == "ESB" ){
				kb_name = "wso2_carbon_enterprise_service_bus";
				cpe = "cpe:/a:wso2:enterprise_service_bus";
				app = "WSO2 Enterprise Service Bus";
			}
			else {
				if( prod == "Data Analytics Server" ){
					kb_name = "wso2_carbon_data_analytics_server";
					cpe = "cpe:/a:wso2:data_analytics_server";
					app = "WSO2 Data Analytics Server";
				}
				else {
					if( prod == "API Manager" ){
						kb_name = "wso2_carbon_api_manager";
						cpe = "cpe:/a:wso2:api_manager";
						app = "WSO2 API Manager";
					}
					else {
						if( prod == "Complex Event Processor" ){
							kb_name = "wso2_carbon_complex_event_processor";
							cpe = "cpe:/a:wso2:complex_event_processor";
							app = "WSO2 Complex Event Processor";
						}
						else {
							if( prod == "Governance Registry" ){
								kb_name = "wso2_carbon_governance_registry";
								cpe = "cpe:/a:wso2:governance_registry";
								app = "WSO2 Governance Registry";
							}
							else {
								if( prod == "Business Process Server" ){
									kb_name = "wso2_carbon_business_process_server";
									cpe = "cpe:/a:wso2:business_process_server";
									app = "WSO2 Business Process Server";
								}
								else {
									if( prod == "Storage Server" ){
										kb_name = "wso2_carbon_storage_server";
										cpe = "cpe:/a:wso2:storage_server";
										app = "WSO2 Storage Server";
									}
									else {
										if( prod == "EI" ){
											kb_name = "wso2_carbon_enterprise_integrator";
											cpe = "cpe:/a:wso2:enterprise_integrator";
											app = "WSO2 Enterprise Integrator";
										}
										else {
											exit( 0 );
										}
									}
								}
							}
						}
					}
				}
			}
		}
		set_kb_item( name: kb_name + "/detected", value: TRUE );
		version = "unknown";
		vers = eregmatch( pattern: "<h1>Version ([0-9.]+)", string: res );
		if( !isnull( vers[1] ) ){
			version = vers[1];
			cpe = cpe + ":" + version;
		}
		else {
			if(prod == "Storage Server"){
				vers = eregmatch( pattern: "Storage Server Version ([0-9.]+)", string: res );
				if(!isnull( vers[1] )){
					version = vers[1];
					cpe = cpe + ":" + version;
				}
			}
		}
		register_product( cpe: cpe, location: "/carbon", port: port, service: "www" );
		log_message( data: build_detection_report( app: app, version: version, install: "/carbon", cpe: cpe, concluded: vers[0], concludedUrl: http_report_vuln_url( port: port, url: url, url_only: TRUE ) ), port: port );
		exit( 0 );
	}
}
exit( 0 );

