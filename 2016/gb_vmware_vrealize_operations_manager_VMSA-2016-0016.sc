CPE = "cpe:/a:vmware:vrealize_operations_manager";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140064" );
	script_cve_id( "CVE-2016-7457" );
	script_tag( name: "cvss_base", value: "8.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:C" );
	script_version( "2021-09-17T13:01:55+0000" );
	script_name( "VMSA-2016-0016: vRealize Operations (vROps) Privilege Escalation Vulnerability" );
	script_xref( name: "URL", value: "http://www.vmware.com/security/advisories/VMSA-2016-0016.html" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Updates are available" );
	script_tag( name: "summary", value: "vRealize Operations (vROps) updates address privilege escalation vulnerability." );
	script_tag( name: "insight", value: "vROps contains a privilege escalation vulnerability. Exploitation of this issue may allow a vROps user who has been assigned a low-privileged role to gain full access over the application. In addition it may be possible to stop and delete Virtual Machines managed by vCenter." );
	script_tag( name: "affected", value: "vRealize Operations 6.x" );
	script_tag( name: "last_modification", value: "2021-09-17 13:01:55 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-30 01:29:00 +0000 (Sun, 30 Jul 2017)" );
	script_tag( name: "creation_date", value: "2016-11-16 15:54:11 +0100 (Wed, 16 Nov 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_family( "VMware Local Security Checks" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_vmware_vrealize_operations_manager_web_detect.sc" );
	script_mandatory_keys( "vmware/vrealize/operations_manager/version", "vmware/vrealize/operations_manager/build" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(!build = get_kb_item( "vmware/vrealize/operations_manager/build" )){
	exit( 0 );
}
if(IsMatchRegexp( version, "^6\\.3\\.0" )){
	if(int( build ) < int( 4443153 )){
		fix = "6.3.0 Build 4443153";
	}
}
if(IsMatchRegexp( version, "^6\\.2\\.1" )){
	if(int( build ) < int( 4418887 )){
		fix = "6.2.1 Build 4418887";
	}
}
if(IsMatchRegexp( version, "^6\\.2\\.0" )){
	if(int( build ) < int( 4419192 )){
		fix = "6.2.0 Build 4419192";
	}
}
if(IsMatchRegexp( version, "^6\\.1\\.0" )){
	if(int( build ) < int( 4422776 )){
		fix = "6.1.0 Build 4422776";
	}
}
if(fix){
	report = report_fixed_ver( installed_version: version + " Build " + build, fixed_version: fix );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

