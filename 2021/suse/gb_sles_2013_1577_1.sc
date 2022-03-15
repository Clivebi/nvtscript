if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2013.1577.1" );
	script_cve_id( "CVE-2012-6085", "CVE-2013-4242", "CVE-2013-4351", "CVE-2013-4402" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:23 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-08-29 01:32:00 +0000 (Tue, 29 Aug 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2013:1577-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES10\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2013:1577-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2013/suse-su-20131577-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gpg' package(s) announced via the SUSE-SU-2013:1577-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This GnuPG LTSS roll-up update fixes two security issues:

 * CVE-2013-4351: GnuPG treated no-usage-permitted keys as all-usages-permitted.
 * CVE-2013-4402: An infinite recursion in the compressed packet parser was fixed.
 * CVE-2013-4242: GnuPG allowed local users to obtain private RSA keys via a cache side-channel attack involving the L3 cache, aka Flush+Reload.
 * CVE-2012-6085: The read_block function in g10/import.c in GnuPG 1.4.x, when importing a key, allowed remote attackers to corrupt the public keyring database or cause a denial of service (application crash) via a crafted length field of an OpenPGP packet.

We also fixed a permission issue on opening new files
(bnc#780943)

Security Issues:

 * CVE-2013-4351
>
 * CVE-2013-4402
>
 * CVE-2013-4242
>
 * CVE-2012-6085
>" );
	script_tag( name: "affected", value: "'gpg' package(s) on SUSE Linux Enterprise Server 10 SP4." );
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
if(release == "SLES10.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "gpg", rpm: "gpg~1.4.2~23.27.1", rls: "SLES10.0SP4" ) )){
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

