if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876840" );
	script_version( "2021-09-02T12:01:30+0000" );
	script_cve_id( "CVE-2018-0737", "CVE-2018-0732", "CVE-2018-0734", "CVE-2019-1552", "CVE-2019-1559", "CVE-2019-1543" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-02 12:01:30 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-03 20:29:00 +0000 (Mon, 03 Jun 2019)" );
	script_tag( name: "creation_date", value: "2019-09-26 02:31:22 +0000 (Thu, 26 Sep 2019)" );
	script_name( "Fedora Update for compat-openssl10 FEDORA-2019-00c25b9379" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-00c25b9379" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ZBEV5QGDRFUZDMNECFXUSN5FMYOZDE4V" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'compat-openssl10'
  package(s) announced via the FEDORA-2019-00c25b9379 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The OpenSSL toolkit provides support for secure communications between
machines. This version of OpenSSL package contains only the libraries
and is provided for compatibility with previous releases and software
that does not support compilation with OpenSSL-1.1." );
	script_tag( name: "affected", value: "'compat-openssl10' package(s) on Fedora 30." );
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
if(release == "FC30"){
	if(!isnull( res = isrpmvuln( pkg: "compat-openssl10", rpm: "compat-openssl10~1.0.2o~7.fc30", rls: "FC30" ) )){
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

