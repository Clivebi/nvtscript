if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.1698.2" );
	script_cve_id( "CVE-2018-12020" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:1698-2)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:1698-2" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20181698-2/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gpg2' package(s) announced via the SUSE-SU-2018:1698-2 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for gpg2 fixes the following security issue:
CVE-2018-12020: GnuPG mishandled the original filename during decryption
 and verification actions, which allowed remote attackers to spoof the
 output that GnuPG sends on file descriptor 2 to other programs that use
 the '--status-fd 2'
 option (bsc#1096745)" );
	script_tag( name: "affected", value: "'gpg2' package(s) on SUSE Linux Enterprise Server 12-SP2." );
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
	if(!isnull( res = isrpmvuln( pkg: "gpg2", rpm: "gpg2~2.0.24~9.3.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gpg2-debuginfo", rpm: "gpg2-debuginfo~2.0.24~9.3.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gpg2-debugsource", rpm: "gpg2-debugsource~2.0.24~9.3.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gpg2-lang", rpm: "gpg2-lang~2.0.24~9.3.1", rls: "SLES12.0SP2" ) )){
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

