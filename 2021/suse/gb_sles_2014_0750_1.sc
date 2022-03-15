if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2014.0750.1" );
	script_cve_id( "CVE-2012-6085", "CVE-2013-4351", "CVE-2013-4402" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:21 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-08-29 01:32:00 +0000 (Tue, 29 Aug 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2014:0750-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2014:0750-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2014/suse-su-20140750-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gpg2' package(s) announced via the SUSE-SU-2014:0750-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This is a SLES 11 SP1 LTSS rollup update for gpg2.

The following security issues have been fixed:

 * CVE-2013-4402: The compressed packet parser in GnuPG allowed remote
 attackers to cause a denial of service (infinite recursion) via a
 crafted OpenPGP message.
 * CVE-2013-4351: GnuPG treated a key flags subpacket with all bits
 cleared (no usage permitted) as if it has all bits set (all usage
 permitted), which might have allowed remote attackers to bypass
 intended cryptographic protection mechanisms by leveraging the
 subkey.
 * CVE-2012-6085: The read_block function in g10/import.c in GnuPG,
 when importing a key, allowed remote attackers to corrupt the public
 keyring database or cause a denial of service (application crash)
 via a crafted length field of an OpenPGP packet.

Also the following non-security bugs have been fixed:

 * set the umask before opening a file for writing (bnc#780943)
 * select proper ciphers when running in FIPS mode (bnc#808958)
 * add missing options to opts table (bnc#778723)" );
	script_tag( name: "affected", value: "'gpg2' package(s) on SUSE Linux Enterprise Server 11 SP1." );
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
if(release == "SLES11.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "gpg2", rpm: "gpg2~2.0.9~25.33.37.6", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gpg2-lang", rpm: "gpg2-lang~2.0.9~25.33.37.6", rls: "SLES11.0SP1" ) )){
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
