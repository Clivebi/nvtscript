if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.0248.1" );
	script_cve_id( "CVE-2016-8632", "CVE-2016-9576", "CVE-2016-9794", "CVE-2016-9806" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-11-28 20:40:00 +0000 (Mon, 28 Nov 2016)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:0248-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:0248-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20170248-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel Live Patch 14 for SLE 12' package(s) announced via the SUSE-SU-2017:0248-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for the Linux Kernel 3.12.60-52_49 fixes several issues.
The following security bugs were fixed:
- CVE-2016-9806: Race condition in the netlink_dump function in
 net/netlink/af_netlink.c in the Linux kernel allowed local users to
 cause a denial of service (double free) or possibly have unspecified
 other impact via a crafted application that made sendmsg system calls,
 leading to a free operation associated with a new dump that started
 earlier than anticipated (bsc#1017589).
- CVE-2016-9794: Race condition in the snd_pcm_period_elapsed function in
 sound/core/pcm_lib.c in the ALSA subsystem in the Linux kernel allowed
 local users to cause a denial of service (use-after-free) or possibly
 have unspecified other impact via a crafted SNDRV_PCM_TRIGGER_START
 command (bsc#1013543).
- CVE-2016-8632: The tipc_msg_build function in net/tipc/msg.c in the
 Linux kernel did not validate the relationship between the minimum
 fragment length and the maximum packet size, which allowed local users
 to gain privileges or cause a denial of service (heap-based buffer
 overflow) by leveraging the CAP_NET_ADMIN capability (bsc#1012852).
- CVE-2016-9576: The blk_rq_map_user_iov function in block/blk-map.c in
 the Linux kernel did not properly restrict the type of iterator, which
 allowed local users to read or write to arbitrary kernel memory
 locations or cause a denial of service (use-after-free) by leveraging
 access to a /dev/sg device (bsc#1014271)." );
	script_tag( name: "affected", value: "'Linux Kernel Live Patch 14 for SLE 12' package(s) on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP 12." );
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
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-3_12_60-52_49-default", rpm: "kgraft-patch-3_12_60-52_49-default~5~2.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-3_12_60-52_49-xen", rpm: "kgraft-patch-3_12_60-52_49-xen~5~2.1", rls: "SLES12.0" ) )){
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

