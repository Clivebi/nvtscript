if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882674" );
	script_version( "2021-09-16T10:32:36+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 10:32:36 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-03-07 05:44:23 +0100 (Tue, 07 Mar 2017)" );
	script_cve_id( "CVE-2017-6074" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-07-19 01:29:00 +0000 (Thu, 19 Jul 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for kernel CESA-2017:0386_01 centos7" );
	script_tag( name: "summary", value: "Check the version of kernel" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The kernel packages contain the Linux kernel,
the core of any Linux operating system.

Security Fix(es):

  * A use-after-free flaw was found in the way the Linux kernel's Datagram
Congestion Control Protocol (DCCP) implementation freed SKB (socket buffer)
resources for a DCCP_PKT_REQUEST packet when the IPV6_RECVPKTINFO option is
set on the socket. A local, unprivileged user could use this flaw to alter
the kernel memory, allowing them to escalate their privileges on the
system. (CVE-2017-6074, Important)" );
	script_tag( name: "affected", value: "kernel on CentOS 7" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2017:0386_01" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2017-March/022323.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS7"){
	if(( res = isrpmvuln( pkg: "kernel", rpm: "kernel~3.10.0~514.10.2.el7", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-abi-whitelists", rpm: "kernel-abi-whitelists~3.10.0~514.10.2.el7", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-debug", rpm: "kernel-debug~3.10.0~514.10.2.el7", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-debug-devel", rpm: "kernel-debug-devel~3.10.0~514.10.2.el7", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~3.10.0~514.10.2.el7", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-doc", rpm: "kernel-doc~3.10.0~514.10.2.el7", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-headers", rpm: "kernel-headers~3.10.0~514.10.2.el7", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-tools", rpm: "kernel-tools~3.10.0~514.10.2.el7", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-tools-libs", rpm: "kernel-tools-libs~3.10.0~514.10.2.el7", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kernel-tools-libs-devel", rpm: "kernel-tools-libs-devel~3.10.0~514.10.2.el7", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "perf", rpm: "perf~3.10.0~514.10.2.el7", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python-perf", rpm: "python-perf~3.10.0~514.10.2.el7", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

