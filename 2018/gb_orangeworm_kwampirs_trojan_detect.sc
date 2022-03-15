if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107306" );
	script_version( "2020-04-06T10:38:44+0000" );
	script_tag( name: "last_modification", value: "2020-04-06 10:38:44 +0000 (Mon, 06 Apr 2020)" );
	script_tag( name: "creation_date", value: "2018-04-26 15:23:05 +0100 (Thu, 26 Apr 2018)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_name( "Orangeworm Kwampirs Trojan Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Malware" );
	script_dependencies( "gb_wmi_access.sc" );
	script_mandatory_keys( "WMI/access_successful" );
	script_xref( name: "URL", value: "https://www.symantec.com/blogs/threat-intelligence/orangeworm-targets-healthcare-us-europe-asia" );
	script_xref( name: "URL", value: "http://www.virusresearch.org/kwampirs-trojan-removal/" );
	script_tag( name: "summary", value: "The script tries to detect the Orangeworm Kwampirs Trojan via various known Indicators of Compromise (IOC)." );
	script_tag( name: "insight", value: "The Orangeworm group is using a repurposed Trojan called Kwampirs to set up persistent remote access after they infiltrate
  victim organizations. Kwampirs is not especially stealthy and can be detected using indicators of compromise and activity on the target system. The Trojan
  evades hash-based detection by inserting a random string in its main executable so its hash is different on each system. However, Kwampirs uses consistent
  services names, configuration files, and similar payload DLLs on the target machine that can be used to detect it." );
	script_tag( name: "impact", value: "Trojan.Kwampirs is a Trojan horse that may open a back door on the compromised computer. It may also download potentially malicious files." );
	script_tag( name: "affected", value: "All Windows Systems." );
	script_tag( name: "solution", value: "A whole cleanup of the infected system is recommended." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("host_details.inc.sc");
require("smb_nt.inc.sc");
infos = kb_smb_wmi_connectinfo();
if(!infos){
	exit( 0 );
}
handle = wmi_connect( host: infos["host"], username: infos["username_wmi_smb"], password: infos["password"] );
if(!handle){
	exit( 0 );
}
query = "SELECT Description, DisplayName, Name, PathName FROM Win32_Service";
services = wmi_query( wmi_handle: handle, query: query );
wmi_close( wmi_handle: handle );
if(!services){
	exit( 0 );
}
services_list = split( buffer: services, keep: FALSE );
for service in services_list {
	if(service == "Description|DisplayName|Name|PathName"){
		continue;
	}
	service_split = split( buffer: service, sep: "|", keep: FALSE );
	if(max_index( service_split ) < 3){
		continue;
	}
	display_name = service_split[1];
	service_name = service_split[2];
	path_name = service_split[3];
	indicators = 0;
	if(ContainsString( service_name, "WmiApSrvEx" )){
		indicators++;
	}
	if(ContainsString( display_name, "WMI Performance Adapter Extension" )){
		indicators++;
	}
	if(ContainsString( path_name, "ControlTrace -Embedding -k" )){
		indicators++;
	}
	if(indicators > 1){
		services_report += service + "\n";
		SERVICES_VULN = TRUE;
	}
}
if(SERVICES_VULN){
	report = "Trojan.Kwampirs, a backdoor Trojan that provides attackers with remote access to this computer, has been found based on the following IOCs:";
	report += "\n\nDescription|DisplayName|Name|PathName\n";
	report += services_report;
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

