if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850795" );
	script_version( "2020-11-19T10:53:01+0000" );
	script_tag( name: "last_modification", value: "2020-11-19 10:53:01 +0000 (Thu, 19 Nov 2020)" );
	script_tag( name: "creation_date", value: "2015-10-13 18:35:00 +0530 (Tue, 13 Oct 2015)" );
	script_cve_id( "CVE-2014-3466", "CVE-2014-3467", "CVE-2014-3468", "CVE-2014-3469" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "SUSE: Security Advisory for gnutls (SUSE-SU-2014:0758-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gnutls'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "GnuTLS has been patched to ensure proper parsing of session ids during the
  TLS/SSL handshake. Additionally, three issues inherited from libtasn1 have
  been fixed.

  These security issues have been fixed:

  * Possible memory corruption during connect (CVE-2014-3466)

  * Multiple boundary check issues could allow DoS (CVE-2014-3467)

  * asn1_get_bit_der() can return negative bit length (CVE-2014-3468)

  * Possible DoS by NULL pointer dereference (CVE-2014-3469)" );
	script_xref( name: "URL", value: "http://www.gnutls.org/security.html#GNUTLS-SA-2014-3" );
	script_tag( name: "affected", value: "gnutls on SUSE Linux Enterprise Server 11 SP3" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "SUSE-SU", value: "2014:0758-1" );
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

