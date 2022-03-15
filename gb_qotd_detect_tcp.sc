if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108896" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-08-28 08:18:31 +0000 (Fri, 28 Aug 2020)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Quote of the Day (qotd) Service Detection (TCP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Service detection" );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "find_service2.sc", "find_service_spontaneous.sc" );
	script_require_ports( "Services/qotd", 17 );
	script_tag( name: "summary", value: "TCP based detection of a Quote of the Day (qotd) service." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
port = service_get_port( default: 17, proto: "qotd" );
banner = get_kb_item( "qotd/tcp/" + port + "/banner" );
if(!banner){
	soc = open_sock_tcp( port );
	if(!soc){
		exit( 0 );
	}
	banner = recv_line( socket: soc, length: 1024 );
	close( soc );
}
if(!banner){
	exit( 0 );
}
if(IsMatchRegexp( banner, " (A\\. A\\. Milne|Albert Einstein|Anonimo|Antico proverbio cinese|Autor desconocido|Charles Dickens|Francisco de Quevedo y Villegas|George Bernard Shaw|Jaime Balmes|Johann Wolfgang von Goethe|Jil Sander|Juana de Asbaje|Konfucius|Lord Philip Chesterfield|Montaigne|Petrarca|Ralph Waldo Emerson|Seneca|Syrus|Werner von Siemens)" ) || IsMatchRegexp( banner, "\\((Albert Einstein|Anatole France|August von Kotzebue|Berthold Brecht|Bertrand Russell|Federico Fellini|Fritz Muliar|Helen Markel|Mark Twain|Oscar Wilde|Tschechisches Sprichwort|Schweizer Sprichwort|Volksweisheit)\\)" ) || ContainsString( banner, "(Juliette Gr" ) || ContainsString( banner, "Dante (Inferno)" ) || ContainsString( banner, "Semel in anno licet insanire." ) || ContainsString( banner, "Oh the nerves, the nerves; the mysteries of this machine called man" ) || ContainsString( banner, "Metastasio (Ipermestra)" ) || ContainsString( banner, "\"\r\nAnonimo" ) || IsMatchRegexp( banner, "^\"[^\"]+\" *Autor desconocido[ \t\r\n]*$" ) || ContainsString( banner, "/usr/games/fortune: not found" ) || IsMatchRegexp( banner, "^\"[^\"]+\"[ \t\r\n]+[A-Za-z -]+[ \t\r\n]+\\([0-9]+(-[0-9]+)?\\)[ \t\r\n]+$" ) || egrep( pattern: "^[A-Za-z. -]+\\([0-9-]+\\)", string: banner )){
	replace_kb_item( name: "qotd/tcp/" + port + "/banner", value: chomp( banner ) );
	set_kb_item( name: "qotd/tcp/detected", value: TRUE );
	set_kb_item( name: "qotd/tcp/" + port + "/detected", value: TRUE );
	service_register( port: port, proto: "qotd" );
	log_message( port: port, data: "A qotd (Quote of the Day) service seems to be running on this port." );
}
exit( 0 );

