if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96199" );
	script_version( "$Revision: 10626 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-25 17:30:18 +0200 (Wed, 25 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2014-03-12 09:32:24 +0200 (Wed, 12 Mar 2014)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Get Windows File-Shares over WMI" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "gb_wmi_access.sc" );
	script_mandatory_keys( "WMI/access_successful" );
	script_tag( name: "summary", value: "Get Windows File-Shares over WMI." );
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
query = "select Description, Name, Path from Win32_share";
sharelist = wmi_query( wmi_handle: handle, query: query );
wmi_close( wmi_handle: handle );
if(sharelist){
	set_kb_item( name: "WMI/Accessible_Shares", value: sharelist );
	report = "The following File-Shares were found:\n\n" + sharelist;
	log_message( port: 0, data: report );
}
exit( 0 );

