if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140140" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "$Revision: 11885 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2017-02-01 12:25:05 +0100 (Wed, 01 Feb 2017)" );
	script_name( "EMC Data Domain Detection (SSH)" );
	script_tag( name: "summary", value: "This script performs SSH based detection of EMC Data Domain." );
	script_tag( name: "qod_type", value: "package" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "This script is Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "emc/data_domain_os/uname" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("host_details.inc.sc");
if(!uname = get_kb_item( "emc/data_domain_os/uname" )){
	exit( 0 );
}
if(!ContainsString( uname, "Data Domain OS" )){
	exit( 0 );
}
set_kb_item( name: "emc/data_domain/installed", value: TRUE );
vb = eregmatch( pattern: "Data Domain OS ([0-9.]+[^-]+)-([0-9]+)", string: uname );
if(!isnull( vb[1] )){
	set_kb_item( name: "emc/data_domain/version/ssh", value: vb[1] );
}
if(!isnull( vb[2] )){
	set_kb_item( name: "emc/data_domain/build/ssh", value: vb[2] );
}
model = ssh_cmd_exec( cmd: "system show modelno" );
if(!isnull( model )){
	set_kb_item( name: "emc/data_domain/model/ssh", value: model );
	if(ContainsString( model, "DD VE" )){
		set_kb_item( name: "emc/data_domain/is_vm/ssh", value: TRUE );
	}
}
exit( 0 );

