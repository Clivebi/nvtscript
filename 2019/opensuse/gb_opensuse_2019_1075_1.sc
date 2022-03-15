if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852381" );
	script_version( "2021-09-07T12:01:40+0000" );
	script_cve_id( "CVE-2019-3855", "CVE-2019-3856", "CVE-2019-3857", "CVE-2019-3858", "CVE-2019-3859", "CVE-2019-3860", "CVE-2019-3861", "CVE-2019-3862", "CVE-2019-3863" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-07 12:01:40 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-15 13:42:00 +0000 (Thu, 15 Oct 2020)" );
	script_tag( name: "creation_date", value: "2019-04-03 06:42:12 +0000 (Wed, 03 Apr 2019)" );
	script_name( "openSUSE: Security Advisory for libssh2_org (openSUSE-SU-2019:1075-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
	script_xref( name: "openSUSE-SU", value: "2019:1075-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-03/msg00040.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libssh2_org'
  package(s) announced via the openSUSE-SU-2019:1075-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libssh2_org fixes the following issues:

  Security issues fixed:

  - CVE-2019-3861: Fixed Out-of-bounds reads with specially crafted SSH
  packets (bsc#1128490).

  - CVE-2019-3862: Fixed Out-of-bounds memory comparison with specially
  crafted message channel request packet (bsc#1128492).

  - CVE-2019-3860: Fixed Out-of-bounds reads with specially crafted SFTP
  packets (bsc#1128481).

  - CVE-2019-3863: Fixed an Integer overflow in user authenticate keyboard
  interactive which could allow out-of-bounds writes with specially
  crafted keyboard responses (bsc#1128493).

  - CVE-2019-3856: Fixed a potential Integer overflow in keyboard
  interactive handling which could allow out-of-bounds write with
  specially crafted payload (bsc#1128472).

  - CVE-2019-3859: Fixed Out-of-bounds reads with specially crafted payloads
  due to unchecked use of _libssh2_packet_require and
  _libssh2_packet_requirev (bsc#1128480).

  - CVE-2019-3855: Fixed a potential Integer overflow in transport read
  which could allow out-of-bounds write with specially crafted payload
  (bsc#1128471).

  - CVE-2019-3858: Fixed a potential zero-byte allocation which could lead
  to an out-of-bounds read with a specially crafted SFTP packet
  (bsc#1128476).

  - CVE-2019-3857: Fixed a potential Integer overflow which could lead to
  zero-byte allocation and out-of-bounds with specially crafted message
  channel request SSH packet (bsc#1128474).

  Other issue addressed:

  - Libbssh2 will stop using keys unsupported types in the known_hosts file
  (bsc#1091236).

  This update was imported from the SUSE:SLE-12:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-1075=1" );
	script_tag( name: "affected", value: "'libssh2_org' package(s) on openSUSE Leap 42.3." );
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
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "libssh2-1", rpm: "libssh2-1~1.4.3~19.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libssh2-1-debuginfo", rpm: "libssh2-1-debuginfo~1.4.3~19.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libssh2-devel", rpm: "libssh2-devel~1.4.3~19.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libssh2_org-debugsource", rpm: "libssh2_org-debugsource~1.4.3~19.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libssh2-1-32bit", rpm: "libssh2-1-32bit~1.4.3~19.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libssh2-1-debuginfo-32bit", rpm: "libssh2-1-debuginfo-32bit~1.4.3~19.3.1", rls: "openSUSELeap42.3" ) )){
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

