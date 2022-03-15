if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875553" );
	script_version( "2021-09-02T13:01:30+0000" );
	script_cve_id( "CVE-2019-9755" );
	script_tag( name: "cvss_base", value: "4.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-02 13:01:30 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-27 03:15:00 +0000 (Mon, 27 Jul 2020)" );
	script_tag( name: "creation_date", value: "2019-04-06 02:12:59 +0000 (Sat, 06 Apr 2019)" );
	script_name( "Fedora Update for ntfs-3g FEDORA-2019-c1e6c6edd9" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC28" );
	script_xref( name: "FEDORA", value: "2019-c1e6c6edd9" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/K6EM2UCXCXQOSP2GURAU2U2IFB6DYYX3" );
	script_tag( name: "summary", value: "The remote host is missing an update for the
  'ntfs-3g' package(s) announced via the FEDORA-2019-c1e6c6edd9 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is
  present on the target host." );
	script_tag( name: "insight", value: "NTFS-3G is a stable, open source, GPL licensed,
  POSIX, read/write NTFS driver for Linux and many other operating systems.
  It provides safe handling of the Windows XP, Windows Server 2003, Windows 2000,
  Windows Vista, Windows Server 2008 and Windows 7 NTFS file systems. NTFS-3G can
  create, remove, rename, move files, directories, hard links, and streams,
  it can read and write normal and transparently compressed files, including
  streams and sparse files, it can handle special files like symbolic links,
  devices, and FIFOs, ACL, extended attributes, moreover it provides full
  file access right and ownership support." );
	script_tag( name: "affected", value: "'ntfs-3g' package(s) on Fedora 28." );
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
if(release == "FC28"){
	if(!isnull( res = isrpmvuln( pkg: "ntfs-3g", rpm: "ntfs-3g~2017.3.23~11.fc28", rls: "FC28" ) )){
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

