if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878332" );
	script_version( "2020-09-28T10:54:24+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-09-28 10:54:24 +0000 (Mon, 28 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-09-26 03:12:46 +0000 (Sat, 26 Sep 2020)" );
	script_name( "Fedora: Security Advisory for gnutls (FEDORA-2020-d12739ca45)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "FEDORA", value: "2020-d12739ca45" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/7NBM6CF2MGZXVONHSVQYH4HCF2F7DIU3" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gnutls'
  package(s) announced via the FEDORA-2020-d12739ca45 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "GnuTLS is a secure communications library implementing the SSL, TLS and DTLS
protocols and technologies around them. It provides a simple C language
application programming interface (API) to access the secure communications
protocols as well as APIs to parse and write X.509, PKCS #12, OpenPGP and
other required structures." );
	script_tag( name: "affected", value: "'gnutls' package(s) on Fedora 33." );
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
if(release == "FC33"){
	if(!isnull( res = isrpmvuln( pkg: "gnutls", rpm: "gnutls~3.6.15~1.fc33", rls: "FC33" ) )){
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

