if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150403" );
	script_version( "2021-03-04T12:22:07+0000" );
	script_tag( name: "last_modification", value: "2021-03-04 12:22:07 +0000 (Thu, 04 Mar 2021)" );
	script_tag( name: "creation_date", value: "2020-11-12 07:11:36 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "openGauss: Authentication Parameters" );
	script_category( ACT_SETTINGS );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Compliance" );
	script_dependencies( "compliance_tests.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Database", type: "entry", value: "postgres", id: 1 );
	script_add_preference( name: "Port", type: "entry", value: "26000", id: 2 );
	script_add_preference( name: "Use 'su - USER' option on gsql commands", type: "radio", value: "no;yes", id: 3 );
	script_add_preference( name: "Use this user for 'su - USER' option on gsql commands", type: "entry", value: "", id: 4 );
	script_xref( name: "URL", value: "https://opengauss.org" );
	script_tag( name: "summary", value: "Set login parameters for scanning openGauss database." );
	exit( 0 );
}
database = script_get_preference( name: "Database", id: 1 );
if( database && database != "" ) {
	set_kb_item( name: "Policy/opengauss/database", value: database );
}
else {
	set_kb_item( name: "Policy/opengauss/database", value: "postgres" );
}
port = script_get_preference( name: "Port", id: 2 );
if( port && port != "" ) {
	set_kb_item( name: "Policy/opengauss/port", value: port );
}
else {
	set_kb_item( name: "Policy/opengauss/port", value: "26000" );
}
use_su = script_get_preference( name: "Use 'su - USER' option on gsql commands", id: 3 );
su_user = script_get_preference( name: "Use this user for 'su - USER' option on gsql commands", id: 4 );
if(use_su && ContainsString( use_su, "yes" )){
	set_kb_item( name: "Policy/opengauss/use_su", value: "yes" );
	if( !isnull( su_user ) ){
		if( !su_user ){
			replace_kb_item( name: "Policy/opengauss/use_su", value: "no" );
		}
		else {
			set_kb_item( name: "Policy/opengauss/su_user", value: su_user );
		}
	}
	else {
		replace_kb_item( name: "Policy/opengauss/use_su", value: "no" );
	}
}
exit( 0 );

