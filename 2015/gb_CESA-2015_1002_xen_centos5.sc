if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882182" );
	script_version( "$Revision: 14058 $" );
	script_cve_id( "CVE-2015-3456" );
	script_tag( name: "cvss_base", value: "7.7" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-06-09 11:02:54 +0200 (Tue, 09 Jun 2015)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for xen CESA-2015:1002 centos5" );
	script_tag( name: "summary", value: "Check the version of xen" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The xen packages contain administration
  tools and the xend service for managing the kernel-xen kernel for virtualization
  on Red Hat Enterprise Linux.

An out-of-bounds memory access flaw was found in the way QEMU's virtual
Floppy Disk Controller (FDC) handled FIFO buffer access while processing
certain FDC commands. A privileged guest user could use this flaw to crash
the guest or, potentially, execute arbitrary code on the host with the
privileges of the host's QEMU process corresponding to the guest.
(CVE-2015-3456)

Red Hat would like to thank Jason Geffner of CrowdStrike for reporting
this issue.

All xen users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing the
updated packages, all running fully-virtualized guests must be restarted
for this update to take effect." );
	script_tag( name: "affected", value: "xen on CentOS 5" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "CESA", value: "2015:1002" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2015-May/021135.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "xen", rpm: "xen~3.0.3~146.el5_11", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xen-devel", rpm: "xen-devel~3.0.3~146.el5_11", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xen-libs", rpm: "xen-libs~3.0.3~146.el5_11", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
