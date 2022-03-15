if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143354" );
	script_version( "2021-07-13T13:08:53+0000" );
	script_tag( name: "last_modification", value: "2021-07-13 13:08:53 +0000 (Tue, 13 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-01-14 10:04:36 +0000 (Tue, 14 Jan 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Huawei EulerOS Detection (SSH Login)" );
	script_tag( name: "summary", value: "SSH login-based detection of Huawei EulerOS." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_require_ports( "Services/ssh", 22 );
	script_mandatory_keys( "ssh/login/euleros/port" );
	exit( 0 );
}
if(!port = get_kb_item( "ssh/login/euleros/port" )){
	exit( 0 );
}
set_kb_item( name: "huawei/euleros/detected", value: TRUE );
set_kb_item( name: "huawei/euleros/ssh-login/port", value: port );
version = "unknown";
euleros_rls = get_kb_item( "ssh/login/euleros/" + port + "/euleros_release" );
vers = eregmatch( pattern: "^EulerOS release ([0-9]+\\.[0-9]+)( \\(SP([0-9]+)(x86_64)?\\))?", string: euleros_rls, icase: TRUE );
if(!isnull( vers[1] )){
	concluded = vers[0];
	concluded_location = "/etc/euleros-release";
	uvp_rls = get_kb_item( "ssh/login/euleros/" + port + "/uvp_release" );
	if( uvp_rls ){
		vers = eregmatch( pattern: "^EulerOS Virtualization.+release ([0-9.]+)", string: uvp_rls, icase: TRUE );
		if(!isnull( vers[1] )){
			concluded = "\n  - UVP:         " + vers[0] + "\n" + "  - Base-System: " + concluded;
			concluded_location = "\n  - UVP:         /etc/uvp-release\n" + "  - Base-System: " + concluded_location;
		}
	}
	else {
		if( !isnull( vers[3] ) ){
			set_kb_item( name: "huawei/euleros/ssh-login/" + port + "/sp", value: vers[3] );
		}
		else {
			set_kb_item( name: "huawei/euleros/ssh-login/" + port + "/sp", value: "0" );
		}
		if(!isnull( vers[4] )){
			set_kb_item( name: "huawei/euleros/ssh-login/oskey_addition", value: vers[4] );
		}
	}
	set_kb_item( name: "huawei/euleros/ssh-login/" + port + "/version", value: vers[1] );
	set_kb_item( name: "huawei/euleros/ssh-login/" + port + "/concluded", value: concluded );
	set_kb_item( name: "huawei/euleros/ssh-login/" + port + "/concluded_location", value: concluded_location );
}
exit( 0 );

