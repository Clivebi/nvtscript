func make_list_unique(  ){
	var ret, args, _x, _z, _a, e, r;
	ret = make_list();
	args = make_list();
	for _x in _FCT_ANON_ARGS {
		if( NASLTypeof( _x ) == "array" ){
			for _z in _x {
				args = make_list( args,
					 _z );
			}
		}
		else {
			args = make_list( args,
				 _x );
		}
	}
	for _a in args {
		e = FALSE;
		for _r in ret {
			if(_a == _r){
				e = TRUE;
				break;
			}
		}
		if(!e){
			ret = make_list( ret,
				 _a );
		}
	}
	return ret;
}
func in_array( search, array, part_match, icase ){
	var search, array, part_match, icase;
	var _val;
	if(NASLTypeof( array ) != "array"){
		set_kb_item( name: "vt_debug_no_array/" + get_script_oid(), value: get_script_oid() + "#-#array#-#in_array" );
		return;
	}
	if(!search || isnull( search )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#search#-#in_array" );
		return;
	}
	if(isnull( icase )){
		icase = FALSE;
	}
	if(icase){
		search = tolower( search );
	}
	for _val in array {
		if(icase){
			_val = tolower( _val );
		}
		if( part_match ){
			if(ContainsString( _val, search )){
				return TRUE;
			}
		}
		else {
			if(_val == search){
				return TRUE;
			}
		}
	}
	return;
}
func array_key_exist( key, array, part_match, bin_search, icase ){
	var key, array, part_match, bin_search, icase;
	var _a;
	if(NASLTypeof( array ) != "array"){
		set_kb_item( name: "vt_debug_no_array/" + get_script_oid(), value: get_script_oid() + "#-#array#-#array_key_exist" );
		return NULL;
	}
	if(isnull( key )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#key#-#array_key_exist" );
		return NULL;
	}
	if(isnull( icase )){
		icase = FALSE;
	}
	if(icase){
		key = tolower( key );
	}
	for _a in keys( array ) {
		if( bin_search ){
			if(!_a){
				_a = raw_string( 0x00 );
			}
		}
		else {
			if(icase){
				_a = tolower( _a );
			}
		}
		if( part_match ){
			if(ContainsString( _a, key )){
				return TRUE;
			}
		}
		else {
			if(_a == key){
				return TRUE;
			}
		}
	}
	return;
}
func is_array(  ){
	var array, _a;
	array = _FCT_ANON_ARGS[0];
	if(!array){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#_FCT_ANON_ARGS[0]#-#is_array" );
		return;
	}
	if(NASLTypeof( array ) != "array"){
		return FALSE;
	}
	if(max_index( array ) == 0){
		for _a in array {
			return TRUE;
		}
		return;
	}
	return TRUE;
}
func join( list, sep ){
	var list, sep;
	var _l, ret;
	if(!list){
		return;
	}
	if(!sep){
		sep = " ";
	}
	for _l in list {
		ret += _l + sep;
	}
	return ereg_replace( string: ret, pattern: sep + "$", replace: "" );
}

