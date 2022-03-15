if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801519" );
	script_version( "$Revision: 14331 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 15:03:05 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2010-10-07 09:42:58 +0200 (Thu, 07 Oct 2010)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2010-3434" );
	script_name( "ClamAV 'find_stream_bounds()' function Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/2455" );
	script_xref( name: "URL", value: "https://wwws.clamav.net/bugzilla/show_bug.cgi?id=2226" );
	script_xref( name: "URL", value: "http://security-tracker.debian.org/tracker/CVE-2010-3434" );
	script_xref( name: "URL", value: "http://git.clamav.net/gitweb?p=clamav-devel.git;a=blob_plain;f=ChangeLog;hb=clamav-0.96.3" );
	script_category( ACT_GATHER_INFO );
	script_family( "Buffer overflow" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_clamav_detect_lin.sc", "gb_clamav_remote_detect.sc", "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/uname" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary code
  on the system with clamd privileges or cause the application to crash." );
	script_tag( name: "affected", value: "ClamAV version before 0.96.3 on Linux" );
	script_tag( name: "insight", value: "The flaw exists due to a buffer overflow error in 'find_stream_bounds()'
  function in 'pdf.c' file within the libclamav." );
	script_tag( name: "solution", value: "Upgrade to ClamAV 0.96.3 or later" );
	script_tag( name: "summary", value: "This host has ClamAV installed, and is prone to buffer overflow
  vulnerability." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
osCheck = get_kb_item( "ssh/login/uname" );
if(isnull( osCheck ) && !ContainsString( osCheck, "Linux" )){
	exit( 0 );
}
port = get_kb_item( "Services/clamd" );
if(!port){
	port = 0;
}
clamVer = get_kb_item( "ClamAV/remote/Ver" );
if(!clamVer){
	clamVer = get_kb_item( "ClamAV/Lin/Ver" );
}
if(!clamVer){
	exit( 0 );
}
if(version_is_less( version: clamVer, test_version: "0.96.3" )){
	security_message( port: port );
}

