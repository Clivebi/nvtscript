if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.3268.1" );
	script_cve_id( "CVE-2020-25650", "CVE-2020-25651", "CVE-2020-25652", "CVE-2020-25653" );
	script_tag( name: "creation_date", value: "2021-06-09 14:56:50 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-19 17:35:00 +0000 (Fri, 19 Feb 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:3268-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:3268-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20203268-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'spice-vdagent' package(s) announced via the SUSE-SU-2020:3268-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for spice-vdagent fixes the following issues:

Security issues fixed:

CVE-2020-25650: Fixed a memory DoS via arbitrary entries in
 `active_xfers` hash table (bsc#1177780).

CVE-2020-25651: Fixed a possible file transfer DoS and information leak
 via `active_xfers` hash map (bsc#1177781).

CVE-2020-25652: Fixed a possibility to exhaust file descriptors in
 `vdagentd` (bsc#1177782).

CVE-2020-25653: Fixed a race condition when the UNIX domain socket peer
 PID retrieved via `SO_PEERCRED` (bsc#1177783)." );
	script_tag( name: "affected", value: "'spice-vdagent' package(s) on SUSE Linux Enterprise Module for Desktop Applications 15-SP2." );
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
if(release == "SLES15.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "spice-vdagent", rpm: "spice-vdagent~0.19.0~3.3.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "spice-vdagent-debuginfo", rpm: "spice-vdagent-debuginfo~0.19.0~3.3.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "spice-vdagent-debugsource", rpm: "spice-vdagent-debugsource~0.19.0~3.3.1", rls: "SLES15.0SP2" ) )){
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

