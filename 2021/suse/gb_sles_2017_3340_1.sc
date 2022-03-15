if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.3340.1" );
	script_cve_id( "CVE-2017-10661", "CVE-2017-16939" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:3340-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:3340-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20173340-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel (Live Patch 13 for SLE 12 SP1)' package(s) announced via the SUSE-SU-2017:3340-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for the Linux Kernel 3.12.69-60_64_32 fixes several issues.
The following security issues were fixed:
- CVE-2017-16939: The XFRM dump policy implementation in
 net/xfrm/xfrm_user.c allowed local users to gain privileges or cause a
 denial of service (use-after-free) via a crafted SO_RCVBUF setsockopt
 system call in conjunction with XFRM_MSG_GETPOLICY Netlink messages
 (bsc#1069708).
- CVE-2017-10661: Race condition in fs/timerfd.c allowed local users to
 gain privileges or cause a denial of service (list corruption or
 use-after-free) via simultaneous file-descriptor operations that
 leverage improper might_cancel queueing (bsc#1053153)." );
	script_tag( name: "affected", value: "'Linux Kernel (Live Patch 13 for SLE 12 SP1)' package(s) on SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP 12-SP1." );
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
if(release == "SLES12.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-3_12_69-60_64_32-default", rpm: "kgraft-patch-3_12_69-60_64_32-default~9~2.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-3_12_69-60_64_32-xen", rpm: "kgraft-patch-3_12_69-60_64_32-xen~9~2.1", rls: "SLES12.0SP1" ) )){
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

