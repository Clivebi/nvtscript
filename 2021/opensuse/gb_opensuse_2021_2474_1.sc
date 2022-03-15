if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.854025" );
	script_version( "2021-08-26T11:01:06+0000" );
	script_cve_id( "CVE-2021-3582", "CVE-2021-3592", "CVE-2021-3593", "CVE-2021-3594", "CVE-2021-3595", "CVE-2021-3607", "CVE-2021-3608", "CVE-2021-3611" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-26 11:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 11:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-28 03:03:45 +0000 (Wed, 28 Jul 2021)" );
	script_name( "openSUSE: Security Advisory for qemu (openSUSE-SU-2021:2474-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.3" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:2474-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/LOEJDVTTKRPTW4JLAPXEN46YAGYFJMDT" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'qemu'
  package(s) announced via the openSUSE-SU-2021:2474-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for qemu fixes the following issues:

     Security issues fixed:

  - CVE-2021-3595: Fixed slirp: invalid pointer initialization may lead to
       information disclosure (tftp) (bsc#1187366)

  - CVE-2021-3592: Fix for slirp: invalid pointer initialization may lead to
       information disclosure (bootp) (bsc#1187364)

  - CVE-2021-3594: Fix for slirp: invalid pointer initialization may lead to
       information disclosure (udp) (bsc#1187367)

  - CVE-2021-3593: Fix for slirp: invalid pointer initialization may lead to
       information disclosure (udp6) (bsc#1187365)

  - CVE-2021-3582: Fix possible mremap overflow in the pvrdma (bsc#1187499)

  - CVE-2021-3607: Ensure correct input on ring init (bsc#1187539)

  - CVE-2021-3608: Fix the ring init error flow (bsc#1187538)

  - CVE-2021-3611: Fix intel-hda segmentation fault due to stack overflow
       (bsc#1187529)" );
	script_tag( name: "affected", value: "'qemu' package(s) on openSUSE Leap 15.3." );
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
if(release == "openSUSELeap15.3"){
	if(!isnull( res = isrpmvuln( pkg: "qemu-s390", rpm: "qemu-s390~4.2.1~11.25.2", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-s390-debuginfo", rpm: "qemu-s390-debuginfo~4.2.1~11.25.2", rls: "openSUSELeap15.3" ) )){
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

