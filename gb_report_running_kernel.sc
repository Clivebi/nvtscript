if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105885" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-03-19T08:40:35+0000" );
	script_tag( name: "last_modification", value: "2021-03-19 08:40:35 +0000 (Fri, 19 Mar 2021)" );
	script_tag( name: "creation_date", value: "2016-09-05 13:45:04 +0200 (Mon, 05 Sep 2016)" );
	script_name( "Report running Linux Kernel" );
	script_tag( name: "summary", value: "This script reports the running Linux Kernel." );
	script_tag( name: "qod_type", value: "package" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_gather_linux_host_infos.sc" );
	script_mandatory_keys( "Host/running_kernel_version" );
	exit( 0 );
}
if(!kv = get_kb_item( "Host/running_kernel_version" )){
	exit( 0 );
}
uname = get_kb_item( "Host/uname" );
report = "The remote host is running Linux Kernel \"" + kv + "\".\n\n";
if(uname){
	report += "Concluded from uname: " + uname + "\n";
}
log_message( port: 0, data: report );
exit( 0 );

