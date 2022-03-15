func create_uddi_xml( ktype, path, key, name ){
	envelope_header = NASLString( "<?xml version='1.0' encoding='UTF-8'?> <s:Envelope" );
	envelope_header = NASLString( envelope_header, " xmlns:s='http://schemas.xmlsoap.org/soap/envelope/'><s:Body>" );
	get_servicedetail = NASLString( "<get_serviceDetail generic='1.0' xmlns='urn:uddi-org:api'>" );
	get_servicedetail = NASLString( get_servicedetail, "<serviceKey>", key, "</serviceKey></get_serviceDetail>" );
	find_business = NASLString( "<find_business generic='1.0' xmlns='urn:uddi-org:api'>" );
	find_business = NASLString( find_business, "<name>", name, "</name></find_business>" );
	find_service = NASLString( "<find_service generic='1.0' xmlns='urn:uddi-org:api' businessKey='", key, "'>" );
	find_service = NASLString( find_service, "<name>", name, "</name></find_service>" );
	close_envelope = NASLString( "</s:Body></s:Envelope>" );
	if(ktype == "UDDI_QUERY_FBUSINESS"){
		method = find_business;
	}
	if(ktype == "UDDI_QUERY_FSERVICE"){
		method = find_service;
	}
	if(ktype == "UDDI_QUERY_GSERVICE_DETAIL"){
		method = get_servicedetail;
	}
	xml = NASLString( envelope_header, method, close_envelope );
	len = strlen( xml );
	finished_message = NASLString( "POST ", path, " HTTP/1.0\\r\\n" );
	finished_message = NASLString( finished_message, "Accept: text/xml\\r\\n" );
	finished_message = NASLString( finished_message, "Accept: multipart/*\\r\\n" );
	finished_message = NASLString( finished_message, "Host: ", get_host_ip(), "\\r\\n" );
	finished_message = NASLString( finished_message, "User-Agent: OPENVAS::SOAP\\r\\n" );
	finished_message = NASLString( finished_message, "Content-Length: ", len, "\\r\\n" );
	finished_message = NASLString( finished_message, "Content-Type: text/xml; charset=utf-8\\r\\n" );
	finished_message = NASLString( finished_message, "SOAPAction: ''\\r\\n\\r\\n", xml );
	return ( finished_message );
}

