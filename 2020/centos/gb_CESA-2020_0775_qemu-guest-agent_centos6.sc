if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883198" );
	script_version( "2021-07-05T11:01:33+0000" );
	script_cve_id( "CVE-2019-14378", "CVE-2019-15890", "CVE-2020-7039" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-05 11:01:33 +0000 (Mon, 05 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-14 03:50:00 +0000 (Sun, 14 Feb 2021)" );
	script_tag( name: "creation_date", value: "2020-03-11 04:00:37 +0000 (Wed, 11 Mar 2020)" );
	script_name( "CentOS: Security Advisory for qemu-guest-agent (CESA-2020:0775)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	script_xref( name: "CESA", value: "2020:0775" );
	script_xref( name: "URL", value: "https://lists.centos.org/pipermail/centos-announce/2020-March/035657.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'qemu-guest-agent'
  package(s) announced via the CESA-2020:0775 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Kernel-based Virtual Machine (KVM) is a full virtualization solution for
Linux on a variety of architectures. The qemu-kvm packages provide the
user-space component for running virtual machines that use KVM.

Security Fix(es):

  * QEMU: slirp: heap buffer overflow during packet reassembly
(CVE-2019-14378)

  * QEMU: slirp: OOB buffer access while emulating tcp protocols in tcp_emu()
(CVE-2020-7039)

  * QEMU: Slirp: use-after-free during packet reassembly (CVE-2019-15890)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section." );
	script_tag( name: "affected", value: "'qemu-guest-agent' package(s) on CentOS 6." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "CentOS6"){
	if(!isnull( res = isrpmvuln( pkg: "qemu-guest-agent", rpm: "qemu-guest-agent~0.12.1.2~2.506.el6_10.6", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-img", rpm: "qemu-img~0.12.1.2~2.506.el6_10.6", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-kvm", rpm: "qemu-kvm~0.12.1.2~2.506.el6_10.6", rls: "CentOS6" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-kvm-tools", rpm: "qemu-kvm-tools~0.12.1.2~2.506.el6_10.6", rls: "CentOS6" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

