if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814564" );
	script_version( "2021-06-25T02:00:34+0000" );
	script_cve_id( "CVE-2018-16847" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-25 02:00:34 +0000 (Fri, 25 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-14 15:01:00 +0000 (Thu, 14 May 2020)" );
	script_tag( name: "creation_date", value: "2018-12-18 07:39:06 +0100 (Tue, 18 Dec 2018)" );
	script_name( "openSUSE: Security Advisory for qemu (openSUSE-SU-2018:4135-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2018:4135-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-12/msg00036.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'qemu'
  package(s) announced via the openSUSE-SU-2018:4135-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for qemu fixes the following issues:

  Security issue fixed:

  - CVE-2018-16847: Fixed an out of bounds r/w buffer access in cmb
  operations (bsc#1114529).

  Non-security issue fixed:

  - Fixed serial console issue that triggered a qemu-kvm bug (bsc#1108474).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1551=1" );
	script_tag( name: "affected", value: "qemu on openSUSE Leap 15.0." );
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
if(release == "openSUSELeap15.0"){
	if(!isnull( res = isrpmvuln( pkg: "qemu", rpm: "qemu~2.11.2~lp150.7.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-arm", rpm: "qemu-arm~2.11.2~lp150.7.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-arm-debuginfo", rpm: "qemu-arm-debuginfo~2.11.2~lp150.7.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-curl", rpm: "qemu-block-curl~2.11.2~lp150.7.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-curl-debuginfo", rpm: "qemu-block-curl-debuginfo~2.11.2~lp150.7.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-dmg", rpm: "qemu-block-dmg~2.11.2~lp150.7.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-dmg-debuginfo", rpm: "qemu-block-dmg-debuginfo~2.11.2~lp150.7.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-gluster", rpm: "qemu-block-gluster~2.11.2~lp150.7.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-gluster-debuginfo", rpm: "qemu-block-gluster-debuginfo~2.11.2~lp150.7.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-iscsi", rpm: "qemu-block-iscsi~2.11.2~lp150.7.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-iscsi-debuginfo", rpm: "qemu-block-iscsi-debuginfo~2.11.2~lp150.7.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-rbd", rpm: "qemu-block-rbd~2.11.2~lp150.7.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-rbd-debuginfo", rpm: "qemu-block-rbd-debuginfo~2.11.2~lp150.7.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-ssh", rpm: "qemu-block-ssh~2.11.2~lp150.7.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-block-ssh-debuginfo", rpm: "qemu-block-ssh-debuginfo~2.11.2~lp150.7.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-debuginfo", rpm: "qemu-debuginfo~2.11.2~lp150.7.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-debugsource", rpm: "qemu-debugsource~2.11.2~lp150.7.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-extra", rpm: "qemu-extra~2.11.2~lp150.7.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-extra-debuginfo", rpm: "qemu-extra-debuginfo~2.11.2~lp150.7.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-guest-agent", rpm: "qemu-guest-agent~2.11.2~lp150.7.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-guest-agent-debuginfo", rpm: "qemu-guest-agent-debuginfo~2.11.2~lp150.7.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ksm", rpm: "qemu-ksm~2.11.2~lp150.7.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-kvm", rpm: "qemu-kvm~2.11.2~lp150.7.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-lang", rpm: "qemu-lang~2.11.2~lp150.7.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-linux-user", rpm: "qemu-linux-user~2.11.2~lp150.7.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-linux-user-debuginfo", rpm: "qemu-linux-user-debuginfo~2.11.2~lp150.7.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-linux-user-debugsource", rpm: "qemu-linux-user-debugsource~2.11.2~lp150.7.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ppc", rpm: "qemu-ppc~2.11.2~lp150.7.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ppc-debuginfo", rpm: "qemu-ppc-debuginfo~2.11.2~lp150.7.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-s390", rpm: "qemu-s390~2.11.2~lp150.7.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-s390-debuginfo", rpm: "qemu-s390-debuginfo~2.11.2~lp150.7.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-testsuite", rpm: "qemu-testsuite~2.11.2~lp150.7.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-tools", rpm: "qemu-tools~2.11.2~lp150.7.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-tools-debuginfo", rpm: "qemu-tools-debuginfo~2.11.2~lp150.7.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-x86", rpm: "qemu-x86~2.11.2~lp150.7.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-x86-debuginfo", rpm: "qemu-x86-debuginfo~2.11.2~lp150.7.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-ipxe", rpm: "qemu-ipxe~1.0.0+~lp150.7.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-seabios", rpm: "qemu-seabios~1.11.0~lp150.7.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-sgabios", rpm: "qemu-sgabios~8~lp150.7.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "qemu-vgabios", rpm: "qemu-vgabios~1.11.0~lp150.7.15.1", rls: "openSUSELeap15.0" ) )){
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

