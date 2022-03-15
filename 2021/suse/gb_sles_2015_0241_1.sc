if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2015.0241.1" );
	script_cve_id( "CVE-2014-3657", "CVE-2014-7823", "CVE-2014-8136" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-05-26T12:07:57+0000" );
	script_tag( name: "last_modification", value: "2021-05-26 12:07:57 +0000 (Wed, 26 May 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "SUSE Linux Enterprise Server: Security Advisory (SUSE-SU-2015:0241-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "URL", value: "https://lists.suse.com/pipermail/sle-security-updates/2015-February/001213.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for 'libvirt'
  package(s) announced via the SUSE-SU-2015:0241-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Please see the references for more information on the vulnerabilities." );
	script_tag( name: "affected", value: "'libvirt' package(s) on SUSE Linux Enterprise Server 12 (ppc64le s390x x86_64), SUSE Linux Enterprise Server 12 (x86_64)" );
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
if(release == "SLES12.0"){
	if(!isnull( res = isrpmvuln( pkg: "libvirt", rpm: "libvirt~1.2.5~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-client", rpm: "libvirt-client~1.2.5~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-client-debuginfo", rpm: "libvirt-client-debuginfo~1.2.5~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon", rpm: "libvirt-daemon~1.2.5~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-config-network", rpm: "libvirt-daemon-config-network~1.2.5~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-config-nwfilter", rpm: "libvirt-daemon-config-nwfilter~1.2.5~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-debuginfo", rpm: "libvirt-daemon-debuginfo~1.2.5~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-interface", rpm: "libvirt-daemon-driver-interface~1.2.5~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-interface-debuginfo", rpm: "libvirt-daemon-driver-interface-debuginfo~1.2.5~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-lxc", rpm: "libvirt-daemon-driver-lxc~1.2.5~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-lxc-debuginfo", rpm: "libvirt-daemon-driver-lxc-debuginfo~1.2.5~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-network", rpm: "libvirt-daemon-driver-network~1.2.5~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-network-debuginfo", rpm: "libvirt-daemon-driver-network-debuginfo~1.2.5~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-nodedev", rpm: "libvirt-daemon-driver-nodedev~1.2.5~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-nodedev-debuginfo", rpm: "libvirt-daemon-driver-nodedev-debuginfo~1.2.5~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-nwfilter", rpm: "libvirt-daemon-driver-nwfilter~1.2.5~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-nwfilter-debuginfo", rpm: "libvirt-daemon-driver-nwfilter-debuginfo~1.2.5~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-qemu", rpm: "libvirt-daemon-driver-qemu~1.2.5~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-qemu-debuginfo", rpm: "libvirt-daemon-driver-qemu-debuginfo~1.2.5~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-secret", rpm: "libvirt-daemon-driver-secret~1.2.5~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-secret-debuginfo", rpm: "libvirt-daemon-driver-secret-debuginfo~1.2.5~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-storage", rpm: "libvirt-daemon-driver-storage~1.2.5~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-storage-debuginfo", rpm: "libvirt-daemon-driver-storage-debuginfo~1.2.5~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-lxc", rpm: "libvirt-daemon-lxc~1.2.5~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-qemu", rpm: "libvirt-daemon-qemu~1.2.5~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-debugsource", rpm: "libvirt-debugsource~1.2.5~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-doc", rpm: "libvirt-doc~1.2.5~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-lock-sanlock", rpm: "libvirt-lock-sanlock~1.2.5~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-lock-sanlock-debuginfo", rpm: "libvirt-lock-sanlock-debuginfo~1.2.5~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-libxl", rpm: "libvirt-daemon-driver-libxl~1.2.5~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-driver-libxl-debuginfo", rpm: "libvirt-daemon-driver-libxl-debuginfo~1.2.5~21.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-daemon-xen", rpm: "libvirt-daemon-xen~1.2.5~21.1", rls: "SLES12.0" ) )){
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

