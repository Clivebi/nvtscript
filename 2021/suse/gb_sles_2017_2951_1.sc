if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.2951.1" );
	script_cve_id( "CVE-2017-6512" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:51 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-04-29 20:24:00 +0000 (Wed, 29 Apr 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:2951-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:2951-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20172951-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'perl' package(s) announced via the SUSE-SU-2017:2951-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for perl fixes the following issues:
Security issue fixed:
- CVE-2017-6512: Race condition in the rmtree and remove_tree functions in
 the File-Path module before 2.13 for Perl allows attackers to set the
 mode on arbitrary files via vectors involving directory-permission
 loosening logic. (bnc#1047178)
Bug fixes:
- reformat baselibs.conf as source validator workaround" );
	script_tag( name: "affected", value: "'perl' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Software Development Kit 11-SP4." );
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
if(release == "SLES11.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "perl-32bit", rpm: "perl-32bit~5.10.0~64.81.3.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl", rpm: "perl~5.10.0~64.81.3.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-Module-Build", rpm: "perl-Module-Build~0.2808.01~0.81.3.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-Test-Simple", rpm: "perl-Test-Simple~0.72~0.81.3.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-base", rpm: "perl-base~5.10.0~64.81.3.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-doc", rpm: "perl-doc~5.10.0~64.81.3.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-x86", rpm: "perl-x86~5.10.0~64.81.3.1", rls: "SLES11.0SP4" ) )){
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

