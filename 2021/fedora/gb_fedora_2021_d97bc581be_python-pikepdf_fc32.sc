if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879357" );
	script_version( "2021-08-23T12:01:00+0000" );
	script_cve_id( "CVE-2021-29421" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-23 12:01:00 +0000 (Mon, 23 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-02 18:47:00 +0000 (Wed, 02 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-04-10 03:04:05 +0000 (Sat, 10 Apr 2021)" );
	script_name( "Fedora: Security Advisory for python-pikepdf (FEDORA-2021-d97bc581be)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-d97bc581be" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/36P4HTLBJPO524WMQWW57N3QRF4RFSJG" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-pikepdf'
  package(s) announced via the FEDORA-2021-d97bc581be advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "pikepdf is a Python library for reading and writing PDF files. pikepdf is
based on QPDF, a powerful PDF manipulation and repair library." );
	script_tag( name: "affected", value: "'python-pikepdf' package(s) on Fedora 32." );
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
	if(!isnull( res = isrpmvuln( pkg: "python-pikepdf", rpm: "python-pikepdf~1.19.4~2.fc32", rls: "FC32" ) )){
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

