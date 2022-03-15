if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2016.0020.1" );
	script_cve_id( "CVE-2015-7512", "CVE-2015-8345" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:09 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-09 15:14:00 +0000 (Wed, 09 Sep 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2016:0020-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2016:0020-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2016/suse-su-20160020-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kvm' package(s) announced via the SUSE-SU-2016:0020-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for kvm fixes the following issues:
Security issues fixed:
- CVE-2015-7512: The receive packet size is now checked in the emulated
 pcnet driver, eliminating buffer overflow and potential security issue
 by malicious guest systems. (bsc#957162)
- CVE-2015-8345: A infinite loop in processing command block list was
 fixed that could be exploit by malicious guest systems (bsc#956829).
Bugs fixed:
- Fix cases of wrong clock values in kvmclock timekeeping (bsc#947164 and
 bsc#953187)
- Enforce pxe rom sizes to ensure migration compatibility. (bsc#950590)" );
	script_tag( name: "affected", value: "'kvm' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Server 11-SP3." );
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
if(release == "SLES11.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "kvm", rpm: "kvm~1.4.2~37.1", rls: "SLES11.0SP3" ) )){
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

