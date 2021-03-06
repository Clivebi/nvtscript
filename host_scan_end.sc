if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103739" );
	script_version( "$Revision: 11890 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 18:13:30 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2013-06-17 10:52:11 +0100 (Mon, 17 Jun 2013)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Host Scan End" );
	script_category( ACT_END );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "This script is Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_tag( name: "summary", value: "This routine is the last action of scanning a host.
It stores information about the applied NVT Feed and Version as well as the
the applied Scanner version.
Finally the time of finishing the scan of this host is determined and stored." );
	exit( 0 );
}
SCRIPT_DESC = "Host Scan End";
require("plugin_feed_info.inc.sc");
require("host_details.inc.sc");
if(OPENVAS_VERSION){
	register_host_detail( name: "scanned_with_scanner", value: OPENVAS_VERSION, desc: SCRIPT_DESC );
}
if(PLUGIN_SET){
	register_host_detail( name: "scanned_with_feedversion", value: PLUGIN_SET, desc: SCRIPT_DESC );
}
if(PLUGIN_FEED){
	register_host_detail( name: "scanned_with_feedtype", value: PLUGIN_FEED, desc: SCRIPT_DESC );
}
set_kb_item( name: "/tmp/stop_time", value: unixtime() );
exit( 0 );

