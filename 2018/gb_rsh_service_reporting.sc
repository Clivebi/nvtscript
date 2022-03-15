if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100080" );
	script_version( "$Revision: 13010 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-01-10 08:59:14 +0100 (Thu, 10 Jan 2019) $" );
	script_tag( name: "creation_date", value: "2018-10-23 12:59:40 +0200 (Tue, 23 Oct 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "rsh Unencrypted Cleartext Login" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Useless services" );
	script_dependencies( "rsh.sc" );
	script_mandatory_keys( "rsh/detected" );
	script_xref( name: "URL", value: "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-1999-0651" );
	script_tag( name: "summary", value: "This remote host is running a rsh service." );
	script_tag( name: "insight", value: "rsh (remote shell) is a command line computer program which
  can execute shell commands as another user, and on another computer across a computer network." );
	script_tag( name: "solution", value: "Disable the rsh service and use alternatives like SSH instead." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
port = get_kb_item( "Services/rsh" );
if(!port){
	port = 514;
}
if(!get_kb_item( "rsh/" + port + "/detected" )){
	exit( 0 );
}
if(!report = get_kb_item( "rsh/" + port + "/service_report" )){
	exit( 0 );
}
security_message( port: port, data: report );
exit( 0 );

