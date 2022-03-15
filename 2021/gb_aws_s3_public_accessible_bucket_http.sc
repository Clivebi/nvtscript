if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117470" );
	script_version( "2021-06-08T09:48:03+0000" );
	script_tag( name: "last_modification", value: "2021-06-08 09:48:03 +0000 (Tue, 08 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-06-08 09:24:04 +0000 (Tue, 08 Jun 2021)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_name( "Amazon AWS / S3 (compatible) Bucket Publicly Accessible (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://mikey96.medium.com/cloud-based-storage-misconfigurations-critical-bounties-361647f78a29" );
	script_xref( name: "URL", value: "https://docs.aws.amazon.com/AmazonS3/latest/userguide/acls.html" );
	script_tag( name: "summary", value: "The Amazon Web Services (AWS) / Simple Storage Service (S3)
  (compatible) bucket is publicly accessible." );
	script_tag( name: "vuldetect", value: "Checks via HTTP if an AWS / S3 bucket is publicly
  accessible." );
	script_tag( name: "impact", value: "Based on the information provided in this bucket an attacker
  might be able to extract sensitive data from the bucket." );
	script_tag( name: "solution", value: "Enable access control lists (ACL) on the bucket to prevent
  public access to sensitive data." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
url = "/";
res = http_get_cache( item: url, port: port );
if(!res || !IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
	exit( 0 );
}
headers = http_extract_headers_from_response( data: res );
body = http_extract_body_from_response( data: res );
if(!headers || !body){
	exit( 0 );
}
if(egrep( string: headers, pattern: "^Content-Type\\s*:\\s*application/xml", icase: TRUE ) && egrep( string: body, pattern: "^\\s*<ListBucketResult[^>]*>", icase: FALSE )){
	report = http_report_vuln_url( port: port, url: url );
	report += "\nExtracted data (truncated):\n\n" + substr( body, 0, 1500 );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

