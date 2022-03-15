if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878326" );
	script_version( "2021-07-21T11:00:56+0000" );
	script_cve_id( "CVE-2020-16150" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-21 11:00:56 +0000 (Wed, 21 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-05 17:47:00 +0000 (Thu, 05 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-09-24 06:33:51 +0000 (Thu, 24 Sep 2020)" );
	script_name( "Fedora: Security Advisory for mbedtls (FEDORA-2020-8b0d59bac6)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "FEDORA", value: "2020-8b0d59bac6" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/IRPBHCQKZXHVKOP5O5EWE7P76AWGUXQJ" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mbedtls'
  package(s) announced via the FEDORA-2020-8b0d59bac6 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Mbed TLS is a light-weight open source cryptographic and SSL/TLS
library written in C. Mbed TLS makes it easy for developers to include
cryptographic and SSL/TLS capabilities in their (embedded)
applications with as little hassle as possible." );
	script_tag( name: "affected", value: "'mbedtls' package(s) on Fedora 32." );
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
if(release == "FC32"){
	if(!isnull( res = isrpmvuln( pkg: "mbedtls", rpm: "mbedtls~2.16.8~1.fc32", rls: "FC32" ) )){
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
