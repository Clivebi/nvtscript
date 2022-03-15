if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.12231" );
	script_version( "2021-03-18T13:55:00+0000" );
	script_tag( name: "last_modification", value: "2021-03-18 13:55:00 +0000 (Thu, 18 Mar 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "RIS (Remote Installation Service) Detection (Windows SMB Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Jorge Pinto And Nelson Gomes" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "summary", value: "SMB login-based detection of RIS (Remote Installation
  Service)." );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("smb_nt.inc.sc");
port = kb_smb_transport();
if(!port){
	port = 139;
}
key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
item = "SourcePath";
value = registry_get_sz( key: key, item: item );
if(!value){
	exit( 0 );
}
if(match( string: value, pattern: "*RemInst*" )){
	report = "The remote host was installed using RIS (Remote Installation Service).";
	log_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

