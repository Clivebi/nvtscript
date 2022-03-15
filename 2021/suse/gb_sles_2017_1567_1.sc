if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.1567.1" );
	script_cve_id( "CVE-2017-9287" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:1567-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:1567-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20171567-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openldap2' package(s) announced via the SUSE-SU-2017:1567-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for openldap2 fixes the following issues:
Security issues fixed:
- CVE-2017-9287: A double free vulnerability in the mdb backend during
 search with page size 0 was fixed (bsc#1041764)
Non security bugs fixed:
- Let OpenLDAP read system-wide certificates by default and don't hide the
 error if the user-specified CA location cannot be read. (bsc#1009470)
- Fix an uninitialised variable that causes startup failure (bsc#1037396)
- Fix an issue with transaction management that can cause server crash
 (bsc#972331)" );
	script_tag( name: "affected", value: "'openldap2' package(s) on OpenStack Cloud Magnum Orchestration 7, SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP2." );
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
	if(!isnull( res = isrpmvuln( pkg: "libldap-2_4-2", rpm: "libldap-2_4-2~2.4.41~18.29.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldap-2_4-2-32bit", rpm: "libldap-2_4-2-32bit~2.4.41~18.29.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldap-2_4-2-debuginfo", rpm: "libldap-2_4-2-debuginfo~2.4.41~18.29.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldap-2_4-2-debuginfo-32bit", rpm: "libldap-2_4-2-debuginfo-32bit~2.4.41~18.29.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openldap2", rpm: "openldap2~2.4.41~18.29.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openldap2-back-meta", rpm: "openldap2-back-meta~2.4.41~18.29.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openldap2-back-meta-debuginfo", rpm: "openldap2-back-meta-debuginfo~2.4.41~18.29.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openldap2-client", rpm: "openldap2-client~2.4.41~18.29.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openldap2-client-debuginfo", rpm: "openldap2-client-debuginfo~2.4.41~18.29.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openldap2-debuginfo", rpm: "openldap2-debuginfo~2.4.41~18.29.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openldap2-debugsource", rpm: "openldap2-debugsource~2.4.41~18.29.1", rls: "SLES12.0SP2" ) )){
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

