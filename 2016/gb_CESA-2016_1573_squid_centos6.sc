if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882538" );
	script_version( "$Revision: 14058 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-08-08 15:12:00 +0530 (Mon, 08 Aug 2016)" );
	script_cve_id( "CVE-2016-5408", "CVE-2016-4051" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for squid CESA-2016:1573 centos6" );
	script_tag( name: "summary", value: "Check the version of squid" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Squid is a high-performance proxy caching
server for web clients, supporting FTP, Gopher, and HTTP data objects.

Security Fix(es):

  * It was found that the fix for CVE-2016-4051 released via RHSA-2016:1138
did not properly prevent the stack overflow in the munge_other_line()
function. A remote attacker could send specially crafted data to the Squid
proxy, which would exploit the cachemgr CGI utility, possibly triggering
execution of arbitrary code. (CVE-2016-5408)

Red Hat would like to thank Amos Jeffries (Squid) for reporting this issue." );
	script_tag( name: "affected", value: "squid on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "CESA", value: "2016:1573" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2016-August/022029.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS6"){
	if(( res = isrpmvuln( pkg: "squid", rpm: "squid~3.1.23~16.el6_8.6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

