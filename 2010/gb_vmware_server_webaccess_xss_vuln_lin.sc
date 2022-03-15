if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801316" );
	script_version( "2020-04-24T07:24:50+0000" );
	script_tag( name: "last_modification", value: "2020-04-24 07:24:50 +0000 (Fri, 24 Apr 2020)" );
	script_tag( name: "creation_date", value: "2010-04-13 16:55:19 +0200 (Tue, 13 Apr 2010)" );
	script_cve_id( "CVE-2010-1137" );
	script_bugtraq_id( 39037 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "VMware WebAccess Cross Site Scripting vulnerability (Linux)" );
	script_xref( name: "URL", value: "http://www.vmware.com/security/advisories/VMSA-2010-0005.html" );
	script_xref( name: "URL", value: "http://lists.vmware.com/pipermail/security-announce/2010/000086.html" );
	script_xref( name: "URL", value: "http://www.vmware.com/resources/techresources/726" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_vmware_prdts_detect_lin.sc" );
	script_mandatory_keys( "VMware/Linux/Installed", "VMware/Server/Linux/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will lets attackers to execute arbitrary web script
  or HTML." );
	script_tag( name: "affected", value: "VMware Server version 1.0" );
	script_tag( name: "insight", value: "The flaws is due to error in 'Server Console' which is not properly validating
  the input data, which allows to inject arbitrary web script or HTML via the name of a virtual machine." );
	script_tag( name: "summary", value: "This host is installed with VMWare Server and is prone to
  Cross-Site Scripting vulnerability." );
	script_tag( name: "solution", value: "Apply the workaround described in the referenced advisories." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
if(!get_kb_item( "VMware/Linux/Installed" )){
	exit( 0 );
}
vmserVer = get_kb_item( "VMware/Server/Linux/Ver" );
if(vmserVer){
	if(version_is_less_equal( version: vmserVer, test_version: "1.0" )){
		report = report_fixed_ver( installed_version: vmserVer, vulnerable_range: "Less or equal to 1.0" );
		security_message( port: 0, data: report );
	}
}

