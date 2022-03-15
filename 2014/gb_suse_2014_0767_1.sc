if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850589" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2014-06-09 13:49:17 +0530 (Mon, 09 Jun 2014)" );
	script_cve_id( "CVE-2014-3466", "CVE-2014-3465" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "openSUSE: Security Advisory for gnutls (openSUSE-SU-2014:0767-1)" );
	script_tag( name: "affected", value: "gnutls on openSUSE 11.4" );
	script_tag( name: "insight", value: "gnutls was patched to fix security vulnerability that could be used to
  disrupt service or potentially allow remote code execution.

  - Memory corruption during connect (CVE-2014-3466)

  - NULL pointer dereference in gnutls_x509_dn_oid_name (CVE-2014-3465)" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "openSUSE-SU", value: "2014:0767-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gnutls'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE11\\.4" );
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
if(release == "openSUSE11.4"){
	if(!isnull( res = isrpmvuln( pkg: "gnutls", rpm: "gnutls~2.8.6~5.29.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gnutls-debuginfo", rpm: "gnutls-debuginfo~2.8.6~5.29.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gnutls-debugsource", rpm: "gnutls-debugsource~2.8.6~5.29.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgnutls-devel", rpm: "libgnutls-devel~2.8.6~5.29.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgnutls-extra-devel", rpm: "libgnutls-extra-devel~2.8.6~5.29.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgnutls-extra26", rpm: "libgnutls-extra26~2.8.6~5.29.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgnutls-extra26-debuginfo", rpm: "libgnutls-extra26-debuginfo~2.8.6~5.29.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgnutls26", rpm: "libgnutls26~2.8.6~5.29.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgnutls26-debuginfo", rpm: "libgnutls26-debuginfo~2.8.6~5.29.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgnutls26-32bit", rpm: "libgnutls26-32bit~2.8.6~5.29.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgnutls26-debuginfo-32bit", rpm: "libgnutls26-debuginfo-32bit~2.8.6~5.29.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgnutls26-debuginfo-x86", rpm: "libgnutls26-debuginfo-x86~2.8.6~5.29.1", rls: "openSUSE11.4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgnutls26-x86", rpm: "libgnutls26-x86~2.8.6~5.29.1", rls: "openSUSE11.4" ) )){
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

