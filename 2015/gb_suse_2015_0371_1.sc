if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850777" );
	script_version( "2020-01-31T07:58:03+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 07:58:03 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2015-10-13 15:27:20 +0530 (Tue, 13 Oct 2015)" );
	script_cve_id( "CVE-2015-0240" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "SUSE: Security Advisory for Samba (SUSE-SU-2015:0371-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Samba'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Samba has been updated to fix one security issue:

  * CVE-2015-0240: Don't call talloc_free on an uninitialized pointer
  (bnc#917376).

  Additionally, these non-security issues have been fixed:

  * Realign the winbind request structure following
  require_membership_of field expansion (bnc#913001).

  * Reuse connections derived from DFS referrals (bso#10123,
  fate#316512).

  * Set domain/workgroup based on authentication callback value
  (bso#11059).

  * Fix spoolss error response marshalling (bso#10984).

  * Fix spoolss EnumJobs and GetJob responses (bso#10905, bnc#898031).

  * Fix handling of bad EnumJobs levels (bso#10898).

  * Fix small memory-leak in the background print process  (bnc#899558).

  * Prune idle or hung connections older than 'winbind request timeout'
  (bso#3204, bnc#872912)." );
	script_tag( name: "affected", value: "Samba on SUSE Linux Enterprise Server 11 SP3" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "SUSE-SU", value: "2015:0371-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=SLES11\\.0SP3" );
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
	if(!isnull( res = isrpmvuln( pkg: "ldapsmb", rpm: "ldapsmb~1.34b~12.56.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldb1", rpm: "libldb1~3.6.3~0.56.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient0", rpm: "libsmbclient0~3.6.3~0.56.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtalloc2", rpm: "libtalloc2~3.6.3~0.56.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtdb1", rpm: "libtdb1~3.6.3~0.56.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtevent0", rpm: "libtevent0~3.6.3~0.56.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwbclient0", rpm: "libwbclient0~3.6.3~0.56.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba", rpm: "samba~3.6.3~0.56.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-client", rpm: "samba-client~3.6.3~0.56.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-krb-printing", rpm: "samba-krb-printing~3.6.3~0.56.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind", rpm: "samba-winbind~3.6.3~0.56.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient0-32bit", rpm: "libsmbclient0-32bit~3.6.3~0.56.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtalloc2-32bit", rpm: "libtalloc2-32bit~3.6.3~0.56.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtdb1-32bit", rpm: "libtdb1-32bit~3.6.3~0.56.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtevent0-32bit", rpm: "libtevent0-32bit~3.6.3~0.56.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwbclient0-32bit", rpm: "libwbclient0-32bit~3.6.3~0.56.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-32bit", rpm: "samba-32bit~3.6.3~0.56.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-client-32bit", rpm: "samba-client-32bit~3.6.3~0.56.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind-32bit", rpm: "samba-winbind-32bit~3.6.3~0.56.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-doc", rpm: "samba-doc~3.6.3~0.56.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient0-x86", rpm: "libsmbclient0-x86~3.6.3~0.56.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtalloc2-x86", rpm: "libtalloc2-x86~3.6.3~0.56.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtdb1-x86", rpm: "libtdb1-x86~3.6.3~0.56.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwbclient0-x86", rpm: "libwbclient0-x86~3.6.3~0.56.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-client-x86", rpm: "samba-client-x86~3.6.3~0.56.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind-x86", rpm: "samba-winbind-x86~3.6.3~0.56.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-x86", rpm: "samba-x86~3.6.3~0.56.1", rls: "SLES11.0SP3" ) )){
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

