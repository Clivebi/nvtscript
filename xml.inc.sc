func xml_open_tag( tag, attributes ){
	var tag, attributes, res, _attr;
	if(isnull( tag )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#tag#-#xml_open_tag" );
		return NULL;
	}
	if(attributes && NASLTypeof( attributes ) != "array"){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#xml_open_tag: attributes parameter not empty but no array passed." );
		return NULL;
	}
	res = "";
	res += "<" + tag;
	if(!isnull( attributes )){
		for _attr in keys( attributes ) {
			res += " " + _attr + "=\"" + xml_escape( str: attributes[_attr] ) + "\"";
		}
	}
	res += ">";
	return res;
}
func xml_close_tag( tag ){
	var tag;
	if(isnull( tag )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#tag#-#xml_close_tag" );
		return NULL;
	}
	return "</" + tag + ">";
}
func xml_tagline( tag, attributes, value ){
	var tag, attributes, value;
	if(isnull( tag )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#tag#-#xml_tagline" );
		return NULL;
	}
	if(attributes && NASLTypeof( attributes ) != "array"){
		set_kb_item( name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#xml_tagline: attributes parameter not empty but no array passed." );
		return NULL;
	}
	return xml_open_tag( tag: tag, attributes: attributes ) + xml_escape( str: value ) + xml_close_tag( tag: tag );
}
func xml_open_comment(  ){
	return "<!--";
}
func xml_close_comment(  ){
	return "-->";
}
func xml_newline(  ){
	return "\n";
}
func xml_escape( str ){
	var str;
	var escape_table, str_escaped, max_idx, i;
	if(isnull( str )){
		set_kb_item( name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#str#-#xml_escape" );
		return NULL;
	}
	escape_table = make_array( "&", "&amp;", "'", "&apos;", "\"", "&quot;", "<", "&lt;", ">", "&gt;" );
	str_escaped = "";
	max_idx = strlen( str );
	for(i = 0;i < max_idx;i++){
		if( !isnull( escape_table[str[i]] ) ) {
			str_escaped += escape_table[str[i]];
		}
		else {
			str_escaped += str[i];
		}
	}
	return str_escaped;
}

