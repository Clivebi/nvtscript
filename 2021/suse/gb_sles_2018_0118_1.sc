if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.0118.1" );
	script_cve_id( "CVE-2017-16548", "CVE-2017-17433", "CVE-2017-17434" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-01 14:14:00 +0000 (Fri, 01 May 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:0118-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2|SLES12\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:0118-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20180118-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rsync' package(s) announced via the SUSE-SU-2018:0118-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for rsync fixes several issues.
These security issues were fixed:
- CVE-2017-17434: The daemon in rsync did not check for fnamecmp filenames
 in the daemon_filter_list data structure (in the recv_files function in
 receiver.c) and also did not apply the sanitize_paths protection
 mechanism to pathnames found in 'xname follows' strings (in the
 read_ndx_and_attrs function in rsync.c), which allowed remote attackers
 to bypass intended access restrictions' (bsc#1071460).
- CVE-2017-17433: The recv_files function in receiver.c in the daemon in
 rsync, proceeded with certain file metadata updates before checking for
 a filename in the daemon_filter_list data structure, which allowed
 remote attackers to bypass intended access restrictions (bsc#1071459).
- CVE-2017-16548: The receive_xattr function in xattrs.c in rsync did not
 check for a trailing '\\\\0' character in an xattr name, which allowed
 remote attackers to cause a denial of service (heap-based buffer
 over-read and application crash) or possibly have unspecified other
 impact by sending crafted data to the daemon (bsc#1066644).
This non-security issue was fixed:
- Stop file upload after errors like a full disk (bsc#1062063)
- Ensure -X flag works even when setting owner/group (bsc#1028842)" );
	script_tag( name: "affected", value: "'rsync' package(s) on OpenStack Cloud Magnum Orchestration 7, SUSE CaaS Platform ALL, SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2." );
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
	if(!isnull( res = isrpmvuln( pkg: "rsync", rpm: "rsync~3.1.0~13.7.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rsync-debuginfo", rpm: "rsync-debuginfo~3.1.0~13.7.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rsync-debugsource", rpm: "rsync-debugsource~3.1.0~13.7.1", rls: "SLES12.0SP2" ) )){
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
if(release == "SLES12.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "rsync", rpm: "rsync~3.1.0~13.7.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rsync-debuginfo", rpm: "rsync-debuginfo~3.1.0~13.7.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rsync-debugsource", rpm: "rsync-debugsource~3.1.0~13.7.1", rls: "SLES12.0SP3" ) )){
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

