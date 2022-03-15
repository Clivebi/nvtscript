if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140667" );
	script_version( "$Revision: 10894 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-08-10 15:09:25 +0200 (Fri, 10 Aug 2018) $" );
	script_tag( name: "creation_date", value: "2018-01-12 09:26:50 +0700 (Fri, 12 Jan 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Citrix Netscaler Detection (SSH)" );
	script_tag( name: "summary", value: "Detection of Citrix Netscaler

This script performs SSH based detection of Citrix NetScaler." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "citrix_netscaler/found" );
	script_xref( name: "URL", value: "https://www.citrix.com/products/netscaler-adc/" );
	exit( 0 );
}
if(!system = get_kb_item( "citrix_netscaler/system" )){
	exit( 0 );
}
port = get_kb_item( "citrix_netscaler/ssh/port" );
set_kb_item( name: "citrix_netscaler/detected", value: TRUE );
set_kb_item( name: "citrix_netscaler/ssh/detected", value: TRUE );
version = "unknown";
vers = eregmatch( pattern: "NetScaler NS([0-9\\.]+): (Build (([0-9\\.]+))(.e)?.nc)?", string: system );
if(!isnull( vers[1] )){
	if( !isnull( vers[3] ) ) {
		version = vers[1] + "." + vers[3];
	}
	else {
		version = vers[1];
	}
	if(!isnull( vers[5] )){
		set_kb_item( name: "citrix_netscaler/enhanced_build", value: TRUE );
	}
	set_kb_item( name: "citrix_netscaler/ssh/" + port + "/version", value: version );
	set_kb_item( name: "citrix_netscaler/ssh/" + port + "/concluded", value: system );
}
exit( 0 );

