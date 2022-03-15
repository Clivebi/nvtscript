func isdigit( a ){
	var a;
	if( ord( a ) >= ord( "0" ) && ord( a ) <= ord( "9" ) ) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}
func revcomp( a, b ){
	var a, b;
	var done, work_a, work_b, rc, lena, lenb, i, subm_a, subm_b, sub_a, sub_b;
	if(!a){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#a#-#revcomp" );
	}
	if(!b){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#b#-#revcomp" );
	}
	if(IsMatchRegexp( a, "^\\s+" ) || IsMatchRegexp( a, "\\s+$" )){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#revcomp: Trailing / leading space passed to 'a' parameter which might show an unexpected behavior." );
	}
	if(IsMatchRegexp( b, "^\\s+" ) || IsMatchRegexp( b, "\\s+$" )){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#revcomp: Trailing / leading space passed to 'b' parameter which might show an unexpected behavior." );
	}
	if(a == b){
		return ( 0 );
	}
	done = 0;
	work_a = a;
	work_b = b;
	rc = 0;
	for(;!done;){
		lena = strlen( work_a );
		lenb = strlen( work_b );
		if(lena == 0){
			if(lenb > 0){
				rc = -1;
				break;
			}
			if(lenb == 0){
				break;
			}
		}
		for(i = 0;i < lena;i++){
			if(i >= lenb){
				done = 1;
				rc = 1;
				break;
			}
			if(isdigit( a: work_a[i] ) && isdigit( a: work_b[i] )){
				subm_a = eregmatch( pattern: "([0-9]+)", string: substr( work_a, i ) );
				subm_b = eregmatch( pattern: "([0-9]+)", string: substr( work_b, i ) );
				sub_a = subm_a[1];
				sub_b = subm_b[1];
				work_a = substr( work_a, i + strlen( sub_a ) );
				work_b = substr( work_b, i + strlen( sub_b ) );
				if(int( sub_a ) > int( sub_b )){
					done = 1;
					rc = 1;
					break;
				}
				if(int( sub_a ) < int( sub_b )){
					done = 1;
					rc = -1;
					break;
				}
				if(int( sub_a ) == int( sub_b )){
					if(strlen( work_a ) == 0 || strlen( work_b ) == 0){
						if( strlen( work_a ) == 0 ){
							if( strlen( work_b ) == 0 ){
								done = 1;
								break;
							}
							else {
								done = 1;
								rc = -1;
								break;
							}
						}
						else {
							done = 1;
							rc = 1;
							break;
						}
					}
					if(work_a[0] == "." && work_b[0] != "."){
						done = 1;
						rc = 1;
						break;
					}
					if(work_a[0] != "." && work_b[0] == "."){
						done = 1;
						rc = -1;
						break;
					}
					break;
				}
			}
			if(ord( work_a[i] ) < ord( work_b[i] )){
				done = 1;
				rc = -1;
				break;
			}
			if(ord( work_a[i] ) > ord( work_b[i] )){
				done = 1;
				rc = 1;
				break;
			}
			if(i == lena - 1 && lenb > lena){
				done = 1;
				rc = -1;
				break;
			}
		}
	}
	return ( rc );
}

