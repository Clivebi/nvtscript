if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882585" );
	script_version( "2021-09-20T10:01:48+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 10:01:48 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-11-08 15:52:50 +0530 (Tue, 08 Nov 2016)" );
	script_cve_id( "CVE-2016-1583", "CVE-2016-5195" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-12-06 22:29:00 +0000 (Thu, 06 Dec 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for kernel CESA-2016:2124 centos5" );
	script_tag( name: "summary", value: "Check the version of kernel" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The kernel packages contain the Linux kernel,
the core of any Linux operating system.

Security Fix(es):

  * A race condition was found in the way the Linux kernel's memory subsystem
handled the copy-on-write (COW) breakage of private read-only memory
mappings. An unprivileged, local user could use this flaw to gain write
access to otherwise read-only memory mappings and thus increase their
privileges on the system. (CVE-2016-5195, Important)

  * It was found that stacking a file system over procfs in the Linux kernel
could lead to a kernel stack overflow due to deep nesting, as demonstrated
by mounting ecryptfs over procfs and creating a recursion by mapping
/proc/environ. An unprivileged, local user could potentially use this flaw
to escalate their privileges on the system. (CVE-2016-1583, Important)

Red Hat would like to thank Phil Oester for reporting CVE-2016-5195.

Bug Fix(es):

  * In some cases, a kernel crash or file system corruption occurred when
running journal mode 'ordered'. The kernel crash was caused by a null
pointer dereference due to a race condition between two journal functions.
The file system corruption occurred due to a race condition between the
do_get_write_access() function and buffer writeout. This update fixes both
race conditions. As a result, neither the kernel crash, nor the file system
corruption now occur. (BZ#1067708)

  * Prior to this update, some Global File System 2 (GFS2) files had
incorrect time stamp values due to two problems with handling time stamps
of such files. The first problem concerned the atime time stamp, which
ended up with an arbitrary value ahead of the actual value, when a GFS2
file was accessed. The second problem was related to the mtime and ctime
time stamp updates, which got lost when a GFS2 file was written to from one
node and read from or written to from another node. With this update, a set
of patches has been applied that fix these problems. As a result, the time
stamps of GFS2 files are now handled correctly. (BZ#1374861)" );
	script_tag( name: "affected", value: "kernel on CentOS 5" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "CESA", value: "2016:2124" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2016-October/022135.html" );
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
	if(( res = isrpmvuln( pkg: "kernel", rpm: "kernel~2.6.18~416.el5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-debug", rpm: "kernel-debug~2.6.18~416.el5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-debug-devel", rpm: "kernel-debug-devel~2.6.18~416.el5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~2.6.18~416.el5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-doc", rpm: "kernel-doc~2.6.18~416.el5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-headers", rpm: "kernel-headers~2.6.18~416.el5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-PAE", rpm: "kernel-PAE~2.6.18~416.el5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-PAE-devel", rpm: "kernel-PAE-devel~2.6.18~416.el5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-xen", rpm: "kernel-xen~2.6.18~416.el5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-xen-devel", rpm: "kernel-xen-devel~2.6.18~416.el5", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

