if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105809" );
	script_version( "2021-04-21T07:59:45+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-21 07:59:45 +0000 (Wed, 21 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-07-13 16:11:18 +0200 (Wed, 13 Jul 2016)" );
	script_name( "Docker Detection (HTTP REST API)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 2375, 2376 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP REST API based detection of Docker." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 2375 );
url = "/version";
buf = http_get_cache( item: url, port: port );
if(!buf || !IsMatchRegexp( buf, "HTTP/1\\.[01] 200" ) || !ContainsString( buf, "application/json" ) || !ContainsString( buf, "ApiVersion" ) || !ContainsString( buf, "Version" )){
	exit( 0 );
}
rep_url = url;
vers = "unknown";
cpe = "cpe:/a:docker:docker";
set_kb_item( name: "docker/installed", value: TRUE );
version = eregmatch( pattern: "Version\":\"([0-9]+[^\"]+)\",", string: buf );
if(!isnull( version[1] )){
	vers = version[1];
	cpe += ":" + vers;
	rep_vers = vers;
	replace_kb_item( name: "docker/version", value: vers );
}
av = eregmatch( pattern: "ApiVersion\":\"([0-9]+[^\"]+)\",", string: buf );
if(!isnull( av[1] )){
	apiversion = av[1];
	set_kb_item( name: "docker/apiversion", value: apiversion );
	rep_vers += " (ApiVersion: " + apiversion + ")";
}
full_json = eregmatch( pattern: "(\\{[^}]+\\})", string: buf );
if(!isnull( full_json[1] )){
	set_kb_item( name: "docker/full_json", value: full_json[1] );
}
register_product( cpe: cpe, location: port + "/tcp", port: port, service: "www" );
if(!apiversion){
	apiversion = "v1.19";
}
url = "/v" + apiversion + "/containers/json?all=1";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
if(ContainsString( buf, "Id" ) && ContainsString( buf, "ImageID" ) && ContainsString( buf, "Names" )){
	if( ContainsString( buf, "}},{" ) ) {
		sep = "}},{";
	}
	else {
		if(ContainsString( buf, "]},{" )){
			sep = "]},{";
		}
	}
	if( sep ) {
		parts = split( buffer: buf, sep: sep, keep: TRUE );
	}
	else {
		parts = split( buf );
	}
	for container in parts {
		_id = eregmatch( pattern: "\"Id\":\"([^\"]+)\"", string: container );
		if(!isnull( _id[1] )){
			id = _id[1];
		}
		_name = eregmatch( pattern: "\"Names\":\\[\"/([^\"]+)\"", string: container );
		if(!isnull( _name[1] )){
			name = _name[1];
		}
		_image = eregmatch( pattern: "\"Image\":\"([^\"]+)\"", string: container );
		if(!isnull( _image[1] )){
			image = _image[1];
		}
		_status = eregmatch( pattern: "\"Status\":\"([^\"]+)\"", string: container );
		if(!isnull( _status[1] )){
			status = _status[1];
		}
		if(!status){
			status = "unknown";
		}
		ports = "";
		p = eregmatch( pattern: "\"Ports\":\\[(.*)\\]", string: container );
		if(!isnull( p[1] )){
			_p = split( buffer: p[1], sep: "},{", keep: FALSE );
			for ip in _p {
				_ip = eregmatch( pattern: "\"IP\":\"([^\"]+)\"", string: ip );
				_privport = eregmatch( pattern: "\"PrivatePort\":([0-9-]+),", string: ip );
				_pupport = eregmatch( pattern: "\"PublicPort\":([0-9-]+),", string: ip );
				_type = eregmatch( pattern: "\"Type\":\"([^\"]+)\"", string: ip );
				if(!_ip[1] || !_privport[1] || !_pupport[1] || !_type[1]){
					continue;
				}
				ports += _ip[1] + ":" + _privport[1] + "->" + _pupport[1] + "/" + _type[1] + ", ";
			}
		}
		if(!id || !name || !image){
			continue;
		}
		set_kb_item( name: "docker/remote/container/" + id + "/id", value: id );
		set_kb_item( name: "docker/remote/container/" + id + "/name", value: name );
		set_kb_item( name: "docker/remote/container/" + id + "/image", value: image );
		set_kb_item( name: "docker/remote/container/" + id + "/state", value: status );
		if(!IsMatchRegexp( status, "^Up " )){
			continue;
		}
		cdata += "Name:  " + name + "\n" + "ID:    " + id + "\n" + "Image  " + image + "\n";
		if( ports && ports != "" ){
			cdata += "Ports: " + ports + "\n";
			set_kb_item( name: "docker/remote/container/" + id + "/ports", value: ports );
		}
		else {
			cdata += "Ports: N/A\n";
		}
		cdata += "\n";
	}
}
report = build_detection_report( app: "Docker", version: rep_vers, install: port + "/tcp", cpe: cpe, concluded: version[0], concludedUrl: rep_url );
if(cdata){
	set_kb_item( name: "docker/container/present", value: TRUE );
	report += "\n\nThe following containers where detected running on the remote host:\n\n" + cdata;
}
log_message( port: port, data: report );
exit( 0 );

