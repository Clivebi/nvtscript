if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882306" );
	script_version( "$Revision: 14058 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-10-23 07:18:01 +0200 (Fri, 23 Oct 2015)" );
	script_cve_id( "CVE-2015-5279" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for kmod-kvm CESA-2015:1925 centos5" );
	script_tag( name: "summary", value: "Check the version of kmod-kvm" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "KVM (Kernel-based Virtual Machine) is a full virtualization solution for
Linux on AMD64 and Intel 64 systems.

A heap buffer overflow flaw was found in the way QEMU's NE2000 NIC
emulation implementation handled certain packets received over the network.
A privileged user inside a guest could use this flaw to crash the QEMU
instance (denial of service) or potentially execute arbitrary code on
the host. (CVE-2015-5279)

Red Hat would like to thank Qinghao Tang of QIHU 360 Inc. for reporting
this issue.

All kvm users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. Note: The procedure in
the Solution section must be performed before this update will take effect." );
	script_tag( name: "affected", value: "kmod-kvm on CentOS 5" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "CESA", value: "2015:1925" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2015-October/021444.html" );
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
	if(( res = isrpmvuln( pkg: "kmod-kvm", rpm: "kmod-kvm~83~274.el5.centos", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kmod-kvm-debug", rpm: "kmod-kvm-debug~83~274.el5.centos", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kvm", rpm: "kvm~83~274.el5.centos", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kvm-qemu-img", rpm: "kvm-qemu-img~83~274.el5.centos", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "kvm-tools", rpm: "kvm-tools~83~274.el5.centos", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

