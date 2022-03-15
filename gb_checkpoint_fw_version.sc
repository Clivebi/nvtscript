if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140454" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2017-10-26 10:52:10 +0700 (Thu, 26 Oct 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Check Point Firewall Version Detection" );
	script_tag( name: "summary", value: "This Script consolidate the via SSH/HTTP detected version of the Check Point
Firewall." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc", "gb_checkpoint_fw_web_detect.sc" );
	script_mandatory_keys( "checkpoint_fw/detected" );
	script_xref( name: "URL", value: "https://www.checkpoint.com/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
source = "ssh";
if(!version = get_kb_item( "checkpoint_fw/" + source + "/version" )){
	source = "http";
	if( !version = get_kb_item( "checkpoint_fw/" + source + "/version" ) ) {
		exit( 0 );
	}
	else {
		os_register_and_report( os: "Check Point Gaia", cpe: "cpe:/o:checkpoint:gaia_os", banner_type: toupper( source ), desc: "Check Point Firewall Version Detection", runs_key: "unixoide" );
	}
}
set_kb_item( name: "checkpoint_fw/version", value: version );
set_kb_item( name: "checkpoint_fw/version_source", value: source );
cpe = "cpe:/o:checkpoint:gaia_os:" + tolower( version );
register_product( cpe: cpe, location: source );
exit( 0 );

