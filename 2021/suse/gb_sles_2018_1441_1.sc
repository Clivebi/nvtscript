if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.1441.1" );
	script_cve_id( "CVE-2013-4233", "CVE-2013-4234" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2013-09-25 18:21:00 +0000 (Wed, 25 Sep 2013)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:1441-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:1441-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20181441-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libmodplug' package(s) announced via the SUSE-SU-2018:1441-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libmodplug fixes the following issues:
- Update to version 0.8.9.0+git20170610.f6dd59a bsc#1022032:
 * PSM: add missing line to commit
 * ABC: prevent possible increment of p past end
 * ABC: ensure read pointer is valid before incrementing
 * ABC: terminate early when things don't work in substitute
 * OKT: add one more bound check
 * FAR: out by one on check
 * ABC: 10 digit ints require null termination
 * PSM: make sure reads occur of only valid ins
 * ABC: cleanup tracks correctly.
 * WAV: check that there is space for both headers
 * OKT: ensure file size is enough to contain data
 * ABC: initialize earlier
 * ABC: ensure array access is bounded correctly.
 * ABC: clean up loop exiting code
 * ABC: avoid possibility of incrementing *p
 * ABC: abort early if macro would be blank
 * ABC: Use blankline more often
 * ABC: Ensure for loop does not increment past end of loop
 * Initialize nPatterns to 0 earlier
 * Check memory position isn't over the memory length
 * ABC: transpose only needs to look at notes (

- Update to version 0.8.9.0+git20171024.e9fc46e:
 * Spelling fixes
 * Bump version number to 0.8.9.0
 * MMCMP: Check that end pointer is within the file size
 * WAV: ensure integer doesn't overflow
 * XM: additional mempos check
 * sndmix: Don't process row if its empty.
 * snd_fx: dont include patterns of zero size in length calc
 * MT2,AMF: prevent OOB reads
- Add patch for broken pc file where quite some upstream refer to modplug
 directly without specifying the subdir it is in.
- Update to version 0.8.8.5
 * Some security issues: CVE-2013-4233, CVE-2013-4234, as well as many
 fixes suggested by static analyzers: clang build-scan, and coverity.
- Stop using dos2unix
- Run through spec-cleaner
- Use full URL in Source tag" );
	script_tag( name: "affected", value: "'libmodplug' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP3." );
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
if(release == "SLES12.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "libmodplug-debugsource", rpm: "libmodplug-debugsource~0.8.9.0+git20170610.f6dd59a~15.4.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmodplug1", rpm: "libmodplug1~0.8.9.0+git20170610.f6dd59a~15.4.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmodplug1-debuginfo", rpm: "libmodplug1-debuginfo~0.8.9.0+git20170610.f6dd59a~15.4.1", rls: "SLES12.0SP3" ) )){
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

