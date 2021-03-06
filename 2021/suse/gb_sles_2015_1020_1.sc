if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2015.1020.1" );
	script_cve_id( "CVE-2014-8169" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2015:1020-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2015:1020-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2015/suse-su-20151020-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'autofs' package(s) announced via the SUSE-SU-2015:1020-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "autofs was updated to fix one security issue.
This security issue was fixed:
- CVE-2014-8169: Prevent potential privilege escalation via interpreter
 load path for program-based automount maps (bnc#917977).
These non-security issues were fixed:
- Dont pass sloppy option for other than nfs mounts (bnc#901448,
 bnc#916203)
- Fix insserv warning at postinstall (bnc#913376)
- Fix autofs.service so that multiple options passed through sysconfig
 AUTOFS_OPTIONS work correctly (bnc#909472)" );
	script_tag( name: "affected", value: "'autofs' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12." );
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
	if(!isnull( res = isrpmvuln( pkg: "autofs", rpm: "autofs~5.0.9~8.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "autofs-debuginfo", rpm: "autofs-debuginfo~5.0.9~8.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "autofs-debugsource", rpm: "autofs-debugsource~5.0.9~8.1", rls: "SLES12.0" ) )){
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

