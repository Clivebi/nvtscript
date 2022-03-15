if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105304" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "$Revision: 11885 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2015-06-24 13:13:10 +0200 (Wed, 24 Jun 2015)" );
	script_name( "F5 LineRate LROS Detection" );
	script_tag( name: "summary", value: "This script performs SSH based detection of F5 LineRate LROS" );
	script_tag( name: "qod_type", value: "package" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "This script is Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "f5/LROS/show_version" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("host_details.inc.sc");
infos = get_kb_item( "f5/LROS/show_version" );
if(!ContainsString( infos, "F5 Networks LROS" )){
	exit( 0 );
}
cpe = "cpe:/a:f5:linerate";
vers = "unknown";
version = eregmatch( pattern: "F5 Networks LROS Version ([0-9.]+[^\r\n ]+)", string: infos );
if(!isnull( version[1] )){
	vers = version[1];
	cpe += ":" + vers;
}
register_product( cpe: cpe, location: "ssh" );
report = "Detected F5 LineRate LROS  (ssh)\n" + "Version: " + vers + "\n";
log_message( port: 0, data: report );
exit( 0 );

