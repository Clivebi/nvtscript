if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2015.1840.1" );
	script_cve_id( "CVE-2015-4000", "CVE-2015-5352", "CVE-2015-5600" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:10 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-20 15:15:00 +0000 (Wed, 20 Jan 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2015:1840-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2015:1840-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2015/suse-su-20151840-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openssh' package(s) announced via the SUSE-SU-2015:1840-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "openssh was updated to fix four security issues.
These security issues were fixed:
- CVE-2015-5352: The x11_open_helper function in channels.c in ssh in
 OpenSSH when ForwardX11Trusted mode is not used, lacked a check of the
 refusal deadline for X connections, which made it easier for remote
 attackers to bypass intended access restrictions via a connection
 outside of the permitted time window (bsc#936695).
- CVE-2015-5600: The kbdint_next_device function in auth2-chall.c in sshd
 in OpenSSH did not properly restrict the processing of
 keyboard-interactive devices within a single connection, which made it
 easier for remote attackers to conduct brute-force attacks or cause a
 denial of service (CPU consumption) via a long and duplicative list in
 the ssh -oKbdInteractiveDevices option, as demonstrated by a modified
 client that provides a different password for each pam element on this
 list (bsc#938746).
- CVE-2015-4000: Removed and disabled weak DH groups (bsc#932483).
- Hardening patch to fix sftp RCE (bsc#903649).
These non-security issues were fixed:
- bsc#914309: sshd inherits oom_adj -17 on SIGHUP causing DoS potential
 for oom_killer.
- bsc#673532: limits.conf fsize change in SLES10SP3 causing problems to
 WebSphere mqm user." );
	script_tag( name: "affected", value: "'openssh' package(s) on SUSE Linux Enterprise Server 11-SP2." );
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
if(release == "SLES11.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "openssh", rpm: "openssh~5.1p1~41.69.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-askpass", rpm: "openssh-askpass~5.1p1~41.69.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssh-askpass-gnome", rpm: "openssh-askpass-gnome~5.1p1~41.69.4", rls: "SLES11.0SP2" ) )){
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

