func docker_build_all_containers_array( type ){
	var type;
	var containers, _id, state, name, ports, image, co;
	if(!type){
		type = "lsc";
	}
	containers = get_kb_list( "docker/" + type + "/container/*/id" );
	if(!containers){
		return;
	}
	for _id in containers {
		state = get_kb_item( "docker/" + type + "/container/" + _id + "/state" );
		name = get_kb_item( "docker/" + type + "/container/" + _id + "/name" );
		ports = get_kb_item( "docker/" + type + "/container/" + _id + "/ports" );
		image = get_kb_item( "docker/" + type + "/container/" + _id + "/image" );
		if(!ports){
			ports = "";
		}
		co[_id] = make_array( "name", name, "id", _id, "image", image, "ports", ports );
	}
	return co;
}
func docker_build_running_containers_array( type ){
	var type;
	var containers, _id, state, name, ports, image, co;
	if(!type){
		type = "lsc";
	}
	containers = get_kb_list( "docker/" + type + "/container/*/id" );
	if(!containers){
		return;
	}
	for _id in containers {
		state = get_kb_item( "docker/" + type + "/container/" + _id + "/state" );
		if(!IsMatchRegexp( state, "^Up " )){
			continue;
		}
		name = get_kb_item( "docker/" + type + "/container/" + _id + "/name" );
		ports = get_kb_item( "docker/" + type + "/container/" + _id + "/ports" );
		image = get_kb_item( "docker/" + type + "/container/" + _id + "/image" );
		if(!ports){
			ports = "";
		}
		co[_id] = make_array( "name", name, "id", _id, "image", image, "ports", ports );
	}
	return co;
}
func docker_get_running_containers( type ){
	var type, ret_array;
	if(type){
		return docker_build_running_containers_array( type: type );
	}
	ret_array = docker_get_running_containers( type: "lsc" );
	if(!ret_array){
		ret_array = docker_get_running_containers( type: "remote" );
	}
	return ret_array;
}
func docker_truncate_id(v){
	if(!v){
		return;
	}
	return substr( v, 0, 11 );
}

