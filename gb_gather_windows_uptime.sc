if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96175" );
	script_version( "$Revision: 10902 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-08-10 16:20:55 +0200 (Fri, 10 Aug 2018) $" );
	script_tag( name: "creation_date", value: "2016-01-26 09:31:15 +0100 (Tue, 26 Jan 2016)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Gather Windows uptime" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "gb_wmi_access.sc" );
	script_mandatory_keys( "WMI/access_successful" );
	script_tag( name: "summary", value: "This script attempts to gather the 'uptime' from a windows host and stores the results in the KB." );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("host_details.inc.sc");
host = get_host_ip();
usrname = get_kb_item( "SMB/login" );
passwd = get_kb_item( "SMB/password" );
if(!host || !usrname || !passwd){
	exit( 0 );
}
domain = get_kb_item( "SMB/domain" );
if(domain){
	usrname = domain + "\\" + usrname;
}
handle = wmi_connect( host: host, username: usrname, password: passwd );
if(!handle){
	exit( 0 );
}
query = "select LastBootUpTime from Win32_OperatingSystem";
wmidata = wmi_query( wmi_handle: handle, query: query );
wmi_close( wmi_handle: handle );
if(wmidata){
	wmiuptime = split( buffer: wmidata, keep: FALSE );
	uptime_match = eregmatch( pattern: "^([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})", string: wmiuptime[1] );
	if(isnull( uptime_match[0] )){
		exit( 0 );
	}
	uptime = mktime( sec: uptime_match[6], min: uptime_match[5], hour: uptime_match[4], mday: uptime_match[3], mon: uptime_match[2], year: uptime_match[1] );
	register_host_detail( name: "uptime", value: uptime );
	set_kb_item( name: "Host/uptime", value: uptime );
}
exit( 0 );

