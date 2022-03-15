if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851167" );
	script_version( "2020-01-31T07:58:03+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 07:58:03 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2016-01-26 06:11:06 +0100 (Tue, 26 Jan 2016)" );
	script_cve_id( "CVE-2015-4000", "CVE-2015-6908" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "SUSE: Security Advisory for openldap2 (SUSE-SU-2016:0224-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openldap2'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update fixes the following security issues:

  - CVE-2015-6908: The ber_get_next function allowed remote attackers to
  cause a denial
  of service (reachable assertion and application crash) via crafted BER
  data, as demonstrated by an attack against slapd. (bsc#945582)

  - CVE-2015-4000: Fix weak Diffie-Hellman size vulnerability. (bsc#937766)

  It also fixes the following non-security bugs:

  - bsc#955210: Unresponsive LDAP host lookups in IPv6 environment

  This update adds the following functionality:

  - fate#319300: SHA2 password hashing module that can be loaded on-demand." );
	script_tag( name: "affected", value: "openldap2 on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Desktop 12" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "SUSE-SU", value: "2016:0224-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(SLED12\\.0SP0|SLES12\\.0SP0)" );
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
if(release == "SLED12.0SP0"){
	if(!isnull( res = isrpmvuln( pkg: "libldap-2_4-2", rpm: "libldap-2_4-2~2.4.41~18.13.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldap-2_4-2-32bit", rpm: "libldap-2_4-2-32bit~2.4.41~18.13.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldap-2_4-2-debuginfo", rpm: "libldap-2_4-2-debuginfo~2.4.41~18.13.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldap-2_4-2-debuginfo-32bit", rpm: "libldap-2_4-2-debuginfo-32bit~2.4.41~18.13.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openldap2-client", rpm: "openldap2-client~2.4.41~18.13.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openldap2-client-debuginfo", rpm: "openldap2-client-debuginfo~2.4.41~18.13.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openldap2-client-debugsource", rpm: "openldap2-client-debugsource~2.4.41~18.13.1", rls: "SLED12.0SP0" ) )){
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
if(release == "SLES12.0SP0"){
	if(!isnull( res = isrpmvuln( pkg: "libldap-2_4-2", rpm: "libldap-2_4-2~2.4.41~18.13.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldap-2_4-2-debuginfo", rpm: "libldap-2_4-2-debuginfo~2.4.41~18.13.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openldap2", rpm: "openldap2~2.4.41~18.13.4", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openldap2-back-meta", rpm: "openldap2-back-meta~2.4.41~18.13.4", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openldap2-back-meta-debuginfo", rpm: "openldap2-back-meta-debuginfo~2.4.41~18.13.4", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openldap2-client", rpm: "openldap2-client~2.4.41~18.13.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openldap2-client-debuginfo", rpm: "openldap2-client-debuginfo~2.4.41~18.13.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openldap2-client-debugsource", rpm: "openldap2-client-debugsource~2.4.41~18.13.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openldap2-debuginfo", rpm: "openldap2-debuginfo~2.4.41~18.13.4", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openldap2-debugsource", rpm: "openldap2-debugsource~2.4.41~18.13.4", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldap-2_4-2-32bit", rpm: "libldap-2_4-2-32bit~2.4.41~18.13.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldap-2_4-2-debuginfo-32bit", rpm: "libldap-2_4-2-debuginfo-32bit~2.4.41~18.13.1", rls: "SLES12.0SP0" ) )){
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

