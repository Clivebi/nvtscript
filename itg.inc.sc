func itg_send_details( itg_id ){
	var itg_id;
	var result, desc, report;
	if(!itg_id){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#itg_id#-#itg_send_details" );
		return;
	}
	result = get_kb_item( NASLString( itg_id + "/result" ) );
	desc = get_kb_item( NASLString( itg_id + "/desc" ) );
	report = "Ergebnis:\t" + result + "\nDetails:\t" + desc + "\n\n";
	log_message( port: 0, proto: "IT-Grundschutz", data: report );
}
func itg_report_list( oid, requirement, status_spec ){
	var oid, requirement, status_spec;
	var results, title, result, _id, not_compliant;
	results = get_kb_list( "1.3.6.1.4.1.25623.1.0." + oid + "/RESULT/*" );
	title = get_kb_item( "1.3.6.1.4.1.25623.1.0." + oid + "/NAME" );
	if( !results ){
		result["Status"] = "Fehler";
	}
	else {
		for _id in keys( results ) {
			if(results[_id] != requirement){
				not_compliant = TRUE;
			}
		}
		if( not_compliant ){
			result["Status"] = "Nicht erfuellt";
		}
		else {
			result["Status"] = "Erfuellt";
		}
	}
	result["Titel"] = "\"" + title + "\" sollte " + status_spec + " werden";
	return result;
}
func itg_report_item( oid, requirement, status_spec ){
	var oid, requirement, status_spec;
	var results, title, result;
	results = get_kb_item( "1.3.6.1.4.1.25623.1.0." + oid + "/RESULT" );
	title = get_kb_item( "1.3.6.1.4.1.25623.1.0." + oid + "/NAME" );
	if( !results ){
		result["Status"] = "Fehler";
	}
	else {
		if( results != requirement ){
			result["Status"] = "Erfuellt";
		}
		else {
			result["Status"] = "Nicht erfuellt";
		}
	}
	result["Titel"] = "\"" + title + "\" sollte " + status_spec + " werden";
	return result;
}
func itg_report( report ){
	var report;
	if(!get_kb_item( "GSHB/silence" )){
		log_message( data: report, port: 0, proto: "Policy/Control" );
	}
}
func itg_start_requirement( level ){
	var level;
	var ITGLevel, selected_level;
	ITGLevel = get_kb_item( "GSHB/level" );
	if( ITGLevel == "Basis" ){
		selected_level = 0;
	}
	else {
		if( ITGLevel == "Standard" ){
			selected_level = 1;
		}
		else {
			selected_level = 2;
		}
	}
	if( level == "Basis" ){
		level = 0;
	}
	else {
		if( level == "Standard" ){
			level = 1;
		}
		else {
			level = 2;
		}
	}
	if(level <= selected_level){
		return TRUE;
	}
	return FALSE;
}
func itg_get_policy_control_result( oid_list ){
	var oid_list;
	var compliant, _oid, kb_compliant, solution, test, kb_note, notes, ret;
	compliant = "yes";
	for _oid in oid_list {
		kb_compliant = get_kb_item( _oid + "/COMPLIANT" );
		if(tolower( kb_compliant ) != "yes"){
			solution += "; " + _oid + ": " + get_kb_item( _oid + "/FIX" );
			if( kb_compliant == "incomplete" && compliant != "no" ){
				compliant = "incomplete";
			}
			else {
				if(kb_compliant == "no"){
					compliant = "no";
				}
			}
		}
		test += "; " + _oid + ": " + get_kb_item( _oid + "/CMD" );
		if(kb_note = get_kb_item( _oid + "/NOTE" )){
			notes += "; " + _oid + ": " + kb_note;
		}
	}
	if( notes ) {
		notes = str_replace( string: notes, find: "; ", replace: "", count: 1 );
	}
	else {
		notes = "";
	}
	if( solution ) {
		solution = str_replace( string: solution, find: "; ", replace: "", count: 1 );
	}
	else {
		solution = "";
	}
	if( test ) {
		test = str_replace( string: test, find: "; ", replace: "", count: 1 );
	}
	else {
		test = "";
	}
	ret = make_array( "compliant", compliant, "solutions", solution, "tests", test, "notes", notes );
	return ( ret );
}
func itg_set_kb_entries( result, desc, title, id ){
	var result, desc, title, id;
	set_kb_item( name: "GSHB/" + NASLString( id ) + "/result", value: result );
	set_kb_item( name: "GSHB/" + NASLString( id ) + "/desc", value: desc );
	set_kb_item( name: "GSHB/" + NASLString( id ) + "/title", value: title );
}
func itg_result_wrong_target(  ){
	return ( "nicht zutreffend" );
}
func itg_desc_wrong_target(  ){
	return ( "Die Anforderung trifft nicht auf das Zielsystem zu." );
}
func itg_no_automatic_test(  ){
	return ( "Diese Vorgabe muss manuell ueberprueft werden." );
}
func itg_translate_result( compliant ){
	var compliant, result;
	if( compliant == "yes" ) {
		result = "erfuellt";
	}
	else {
		if( compliant == "incomplete" ) {
			result = "Fehler";
		}
		else {
			result = "nicht erfuellt";
		}
	}
	return ( result );
}

