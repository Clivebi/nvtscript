if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2014.0758.1" );
	script_cve_id( "CVE-2014-3466", "CVE-2014-3467", "CVE-2014-3468", "CVE-2014-3469" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:21 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-16 14:30:00 +0000 (Mon, 16 Nov 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2014:0758-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2014:0758-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2014/suse-su-20140758-1/" );
	script_xref( name: "URL", value: "http://www.gnutls.org/security.html#GNUTLS-SA-2014-3" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gnutls' package(s) announced via the SUSE-SU-2014:0758-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "GnuTLS has been patched to ensure proper parsing of session ids during the TLS/SSL handshake. Additionally, three issues inherited from libtasn1 have been fixed.

Further information is available at [link moved to references] These security issues have been fixed:
 * Possible memory corruption during connect (CVE-2014-3466)
 * Multiple boundary check issues could allow DoS (CVE-2014-3467)
 * asn1_get_bit_der() can return negative bit length (CVE-2014-3468)
 * Possible DoS by NULL pointer dereference (CVE-2014-3469)
Security Issue references:
 * CVE-2014-3466" );
	script_tag( name: "affected", value: "'gnutls' package(s) on SUSE Linux Enterprise Desktop 11 SP3, SUSE Linux Enterprise High Availability Extension 11 SP3, SUSE Linux Enterprise Server 11 SP3, SUSE Linux Enterprise Software Development Kit 11 SP3." );
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
	if(!isnull( res = isrpmvuln( pkg: "gnutls", rpm: "gnutls~2.4.1~24.39.51.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgnutls-extra26", rpm: "libgnutls-extra26~2.4.1~24.39.51.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgnutls26", rpm: "libgnutls26~2.4.1~24.39.51.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgnutls26-32bit", rpm: "libgnutls26-32bit~2.4.1~24.39.51.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgnutls26-x86", rpm: "libgnutls26-x86~2.4.1~24.39.51.1", rls: "SLES11.0SP3" ) )){
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
