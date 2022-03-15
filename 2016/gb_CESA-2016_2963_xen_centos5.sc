if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882613" );
	script_version( "$Revision: 14058 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-12-21 05:44:51 +0100 (Wed, 21 Dec 2016)" );
	script_cve_id( "CVE-2016-9637" );
	script_tag( name: "cvss_base", value: "3.7" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for xen CESA-2016:2963 centos5" );
	script_tag( name: "summary", value: "Check the version of xen" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Xen is a virtual machine monitor

Security Fix(es):

  * An out of bounds array access issue was found in the Xen virtual machine
monitor, built with the QEMU ioport support. It could occur while doing
ioport read/write operations, if guest was to supply a 32bit address
parameter. A privileged guest user/process could use this flaw to
potentially escalate their privileges on a host. (CVE-2016-9637)

Red Hat would like to thank the Xen project for reporting this issue." );
	script_tag( name: "affected", value: "xen on CentOS 5" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "CESA", value: "2016:2963" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2016-December/022181.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS5"){
	if(( res = isrpmvuln( pkg: "xen", rpm: "xen~3.0.3~148.el5_11", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xen-devel", rpm: "xen-devel~3.0.3~148.el5_11", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xen-libs", rpm: "xen-libs~3.0.3~148.el5_11", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

