if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818472" );
	script_version( "2021-09-22T05:42:45+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-22 05:42:45 +0000 (Wed, 22 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-09 01:17:09 +0000 (Thu, 09 Sep 2021)" );
	script_name( "Fedora: Security Advisory for testdisk (FEDORA-2021-4dd269a76c)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC35" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-4dd269a76c" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/APA36AIKASVF5CXZS37ABXJI32NI3WVE" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'testdisk'
  package(s) announced via the FEDORA-2021-4dd269a76c advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Tool to check and undelete partition. Works with FAT12, FAT16, FAT32,
NTFS, ext2, ext3, ext4, btrfs, BeFS, CramFS, HFS, JFS, Linux Raid, Linux
Swap, LVM, LVM2, NSS, ReiserFS, UFS, XFS.
PhotoRec is a signature based file recovery utility. It handles more than
440 file formats including JPG, MSOffice, OpenOffice documents." );
	script_tag( name: "affected", value: "'testdisk' package(s) on Fedora 35." );
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
if(release == "FC35"){
	if(!isnull( res = isrpmvuln( pkg: "testdisk", rpm: "testdisk~7.1~7.fc35", rls: "FC35" ) )){
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

