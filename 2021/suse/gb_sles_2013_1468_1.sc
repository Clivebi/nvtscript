if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2013.1468.1" );
	script_cve_id( "CVE-2013-4124" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:23 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2013:1468-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2013:1468-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2013/suse-su-20131468-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Samba' package(s) announced via the SUSE-SU-2013:1468-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The Samba server suite received a security update to fix a denial of service problem in integer wrap protection.
(CVE-2013-4124).

Additionally, the following stability fixes are included in this update:

 * Fix libreplace license ambiguity. (bnc#765270)
 * Document idmap_ad rfc2307 attribute requirements.
(bnc#820531)
 * The pam_winbind require_membership_of option allows for a list of SID, but currently only provides buffer space for ~20. (bnc#806501).

Security Issue reference:

 * CVE-2013-4124
>" );
	script_tag( name: "affected", value: "'Samba' package(s) on SUSE Linux Enterprise Desktop 11 SP3, SUSE Linux Enterprise Server 11 SP3, SUSE Linux Enterprise Software Development Kit 11 SP3." );
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
	if(!isnull( res = isrpmvuln( pkg: "ldapsmb", rpm: "ldapsmb~1.34b~12.42.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libldb1", rpm: "libldb1~3.6.3~0.42.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient0", rpm: "libsmbclient0~3.6.3~0.42.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient0-32bit", rpm: "libsmbclient0-32bit~3.6.3~0.42.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsmbclient0-x86", rpm: "libsmbclient0-x86~3.6.3~0.42.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtalloc2", rpm: "libtalloc2~3.6.3~0.42.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtalloc2-32bit", rpm: "libtalloc2-32bit~3.6.3~0.42.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtalloc2-x86", rpm: "libtalloc2-x86~3.6.3~0.42.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtdb1", rpm: "libtdb1~3.6.3~0.42.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtdb1-32bit", rpm: "libtdb1-32bit~3.6.3~0.42.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtdb1-x86", rpm: "libtdb1-x86~3.6.3~0.42.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtevent0", rpm: "libtevent0~3.6.3~0.42.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtevent0-32bit", rpm: "libtevent0-32bit~3.6.3~0.42.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwbclient0", rpm: "libwbclient0~3.6.3~0.42.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwbclient0-32bit", rpm: "libwbclient0-32bit~3.6.3~0.42.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwbclient0-x86", rpm: "libwbclient0-x86~3.6.3~0.42.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba", rpm: "samba~3.6.3~0.42.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-32bit", rpm: "samba-32bit~3.6.3~0.42.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-client", rpm: "samba-client~3.6.3~0.42.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-client-32bit", rpm: "samba-client-32bit~3.6.3~0.42.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-client-x86", rpm: "samba-client-x86~3.6.3~0.42.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-doc", rpm: "samba-doc~3.6.3~0.42.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-krb-printing", rpm: "samba-krb-printing~3.6.3~0.42.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind", rpm: "samba-winbind~3.6.3~0.42.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind-32bit", rpm: "samba-winbind-32bit~3.6.3~0.42.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-winbind-x86", rpm: "samba-winbind-x86~3.6.3~0.42.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "samba-x86", rpm: "samba-x86~3.6.3~0.42.1", rls: "SLES11.0SP3" ) )){
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

