if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113766" );
	script_version( "2020-09-30T09:30:12+0000" );
	script_tag( name: "last_modification", value: "2020-09-30 09:30:12 +0000 (Wed, 30 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-09-30 08:50:29 +0000 (Wed, 30 Sep 2020)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_name( "rlogin Passwordless Login" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "gb_rlogin_detect.sc" );
	script_mandatory_keys( "rlogin/detected", "rlogin/nopass" );
	script_tag( name: "summary", value: "The rlogin service allows root access without a password." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "This vulnerability allows an attacker to gain
  complete control over the target system." );
	script_tag( name: "solution", value: "Disable the rlogin service and use alternatives like SSH instead." );
	exit( 0 );
}
require("host_details.inc.sc");
if(!get_kb_item( "rlogin/nopass" )){
	exit( 0 );
}
if(!port = get_kb_item( "rlogin/port" )){
	exit( 0 );
}
report = "It was possible to gain root access without a password.";
security_message( data: report, port: port );
exit( 0 );

