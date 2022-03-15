if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96022" );
	script_version( "$Revision: 13295 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-01-25 14:33:05 +0100 (Fri, 25 Jan 2019) $" );
	script_tag( name: "creation_date", value: "2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Reading Apache CustomLogfiles (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2010 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB" );
	script_dependencies( "smb_reg_service_pack.sc", "GSHB/GSHB_WMI_Apache.sc", "GSHB/GSHB_Read_Apache_Config.sc" );
	script_tag( name: "summary", value: "Reading Apache CustomLogfiles" );
	exit( 0 );
}
require("GSHB_read_file.inc.sc");
require("smb_nt.inc.sc");
kbpath = get_kb_item( "WMI/Apache/RootPath" );
if(ContainsString( kbpath, "None" )){
	set_kb_item( name: "GSHB/Apache/404erError", value: "None" );
	set_kb_item( name: "GSHB/Apache/403erError", value: "None" );
	set_kb_item( name: "GSHB/Apache/404erError/log", value: "IT-Grundschutz: No Apache Installed" );
	log_message( port: 0, proto: "IT-Grundschutz", data: NASLString( "No Apache Installed" ) + NASLString( "\\n" ) );
	exit( 0 );
}
customlogfile = get_kb_item( "GSHB/Apache/CustomLog" );
customlogfile = ereg_replace( pattern: "/", replace: "\\", string: customlogfile );
customlogfile = split( buffer: customlogfile, sep: "|", keep: 0 );
for(c = 0;c < max_index( customlogfile );c++){
	if(!ContainsString( "", customlogfile[c] )){
		checkpath = eregmatch( pattern: ".*:.*", string: customlogfile[c] );
		if( isnull( checkpath ) ){
			path = split( buffer: kbpath, sep: ":", keep: FALSE );
			file = path[1] + customlogfile[c];
			share = path[0] + "$";
		}
		else {
			path = split( buffer: customlogfile[c], sep: ":", keep: FALSE );
			file = path[1];
			share = path[0] + "$";
		}
		customlog = GSHB_read_file( share: share, file: file, offset: 0 );
		if( !customlog ){
			log_message( port: 0, proto: "IT-Grundschutz", data: "Cannot access/open the Apache CustomLogfile: " + share + file );
		}
		else {
			Error404 = egrep( pattern: ".*GET .* 404 .*", string: customlog );
			Error403 = egrep( pattern: ".*GET .* 403 .*", string: customlog );
			if( Error404 ){
				httpError404 += NASLString( share + file + ": has 404 Errors!" ) + "\n";
			}
			else {
				httpError404 += NASLString( share + file + ": has no 404 Errors!" ) + "\n";
			}
			if( Error403 ){
				httpError403 = httpError403 + NASLString( share + file + ": has 403 Errors!" ) + "\n";
			}
			else {
				httpError403 = httpError403 + NASLString( share + file + ": has no 403 Errors!" ) + "\n";
			}
		}
	}
}
if(!httpError404){
	httpError404 = "None";
}
if(!httpError403){
	httpError403 = "None";
}
set_kb_item( name: "GSHB/Apache/404Error", value: httpError404 );
set_kb_item( name: "GSHB/Apache/403Error", value: httpError403 );
exit( 0 );

