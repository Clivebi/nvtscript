if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.0264.1" );
	script_cve_id( "CVE-2016-10009", "CVE-2016-10010", "CVE-2016-10011", "CVE-2016-10012", "CVE-2016-8858" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-09-11 10:29:00 +0000 (Tue, 11 Sep 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:0264-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:0264-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20170264-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openssh' package(s) announced via the SUSE-SU-2017:0264-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for openssh fixes several issues.
These security issues were fixed:
- CVE-2016-8858: The kex_input_kexinit function in kex.c allowed remote
 attackers to cause a denial of service (memory consumption) by sending
 many duplicate KEXINIT requests (bsc#1005480).
- CVE-2016-10012: The shared memory manager (associated with
 pre-authentication compression) did not ensure that a bounds check is
 enforced by all compilers, which might allowed local users to gain
 privileges by leveraging access to a sandboxed privilege-separation
 process, related to the m_zback and m_zlib data structures (bsc#1016370).
- CVE-2016-10009: Untrusted search path vulnerability in ssh-agent.c
 allowed remote attackers to execute arbitrary local PKCS#11 modules by
 leveraging control over a forwarded agent-socket (bsc#1016366).
- CVE-2016-10010: When forwarding unix domain sockets with privilege
 separation disabled, the resulting sockets have be created as 'root'
 instead of the authenticated user. Forwarding unix domain sockets
 without privilege separation enabled is now rejected.
- CVE-2016-10011: authfile.c in sshd did not properly consider the effects
 of realloc on buffer contents, which might allowed local users to obtain
 sensitive private-key information by leveraging access to a
 privilege-separated child process (bsc#1016369).
These non-security issues were fixed:
- Adjusted suggested command for removing conflicting server keys from the
 known_hosts file (bsc#1006221)
- Properly verify CIDR masks in configuration (bsc#1005893)" );
	script_tag( name: "affected", value: "'openssh' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2." );
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
if(release == "SLES12.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "openssh", rpm: "openssh~7.2p2~66.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-askpass-gnome", rpm: "openssh-askpass-gnome~7.2p2~66.3", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-askpass-gnome-debuginfo", rpm: "openssh-askpass-gnome-debuginfo~7.2p2~66.3", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-debuginfo", rpm: "openssh-debuginfo~7.2p2~66.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-debugsource", rpm: "openssh-debugsource~7.2p2~66.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-fips", rpm: "openssh-fips~7.2p2~66.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-helpers", rpm: "openssh-helpers~7.2p2~66.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-helpers-debuginfo", rpm: "openssh-helpers-debuginfo~7.2p2~66.1", rls: "SLES12.0SP2" ) )){
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

