if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.2860.1" );
	script_cve_id( "CVE-2018-1000026", "CVE-2018-10902", "CVE-2018-10938", "CVE-2018-5390" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:33:00 +0000 (Wed, 09 Oct 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:2860-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:2860-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20182860-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel (Live Patch 17 for SLE 12 SP2)' package(s) announced via the SUSE-SU-2018:2860-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for the Linux Kernel 4.4.103-92_56 fixes several issues.

The following security issues were fixed:
CVE-2018-5390: Prevent very expensive calls to tcp_collapse_ofo_queue()
 and tcp_prune_ofo_queue() for every incoming TCP packet which can lead
 to a denial of service (bsc#1102682).

CVE-2018-1000026: Fixed an insufficient input validation in bnx2x
 network card driver that can result in DoS via very large, specially
 crafted packet to the bnx2x card due to a network card firmware
 assertion that will take the card offline (bsc#1096723).

CVE-2018-10938: Fixed an infinite loop in the cipso_v4_optptr() function
 leading to a denial-of-service via crafted network packets (bsc#1106191).

CVE-2018-10902: It was found that the raw midi kernel driver did not
 protect against concurrent access which lead to a double realloc (double
 free) in snd_rawmidi_input_params() and snd_rawmidi_output_status(),
 allowing a malicious local attacker to use this for privilege escalation
 (bsc#1105323)." );
	script_tag( name: "affected", value: "'Linux Kernel (Live Patch 17 for SLE 12 SP2)' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for SAP 12-SP2." );
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
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_103-92_53-default", rpm: "kgraft-patch-4_4_103-92_53-default~9~2.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_103-92_56-default", rpm: "kgraft-patch-4_4_103-92_56-default~9~2.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_114-92_64-default", rpm: "kgraft-patch-4_4_114-92_64-default~7~2.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_114-92_67-default", rpm: "kgraft-patch-4_4_114-92_67-default~7~2.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_74-92_38-default", rpm: "kgraft-patch-4_4_74-92_38-default~12~2.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_90-92_45-default", rpm: "kgraft-patch-4_4_90-92_45-default~10~2.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_90-92_50-default", rpm: "kgraft-patch-4_4_90-92_50-default~10~2.1", rls: "SLES12.0SP2" ) )){
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

