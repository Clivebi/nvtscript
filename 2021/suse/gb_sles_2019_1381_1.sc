if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.1381.1" );
	script_cve_id( "CVE-2019-11068", "CVE-2019-5419" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:24 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:1381-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:1381-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20191381-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rmt-server' package(s) announced via the SUSE-SU-2019:1381-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for rmt-server to version 2.1.4 fixes the following issues:
Fix duplicate nginx location in rmt-server-pubcloud (bsc#1135222)

Mirror additional repos that were enabled during mirroring (bsc#1132690)

Make service IDs consistent across different RMT instances (bsc#1134428)

Make SMT data import scripts faster (bsc#1134190)

Fix incorrect triggering of registration sharing (bsc#1129392)

Fix license mirroring issue in some non-SUSE repositories (bsc#1128858)

Set CURLOPT_LOW_SPEED_LIMIT to prevent downloads from getting stuck
 (bsc#1107806)

Truncate the RMT lockfile when writing a new PID (bsc#1125770)

Fix missing trailing slashes on custom repository import from SMT
 (bsc#1118745)

Zypper authentication plugin (fate#326629)

Instance verification plugin in rmt-server-pubcloud (fate#326629)

Update dependencies to fix vulnerabilities in rails (CVE-2019-5419,
 bsc#1129271) and nokogiri (CVE-2019-11068, bsc#1132160)

Allow RMT registration to work under HTTP as well as HTTPS.

Offline migration from SLE 15 to SLE 15 SP1 will add Python2 module

Online migrations will automatically add additional modules to the
 client systems depending on the base product

Supply log severity to journald

Breaking Change: Added headers to generated CSV files" );
	script_tag( name: "affected", value: "'rmt-server' package(s) on SUSE Linux Enterprise Module for Server Applications 15." );
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
if(release == "SLES15.0"){
	if(!isnull( res = isrpmvuln( pkg: "rmt-server", rpm: "rmt-server~2.1.4~3.17.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rmt-server-debuginfo", rpm: "rmt-server-debuginfo~2.1.4~3.17.1", rls: "SLES15.0" ) )){
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

