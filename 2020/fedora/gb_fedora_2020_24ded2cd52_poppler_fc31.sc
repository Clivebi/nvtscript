if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877459" );
	script_version( "2021-07-21T02:01:11+0000" );
	script_cve_id( "CVE-2019-14494" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-21 02:01:11 +0000 (Wed, 21 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-09 02:15:00 +0000 (Mon, 09 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-02-11 04:02:56 +0000 (Tue, 11 Feb 2020)" );
	script_name( "Fedora: Security Advisory for poppler (FEDORA-2020-24ded2cd52)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2020-24ded2cd52" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/AHYAM32PALHQXL3O4DKIJ3EJB6AKBOVC" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'poppler'
  package(s) announced via the FEDORA-2020-24ded2cd52 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "poppler is a PDF rendering library." );
	script_tag( name: "affected", value: "'poppler' package(s) on Fedora 31." );
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
if(release == "FC31"){
	if(!isnull( res = isrpmvuln( pkg: "poppler", rpm: "poppler~0.73.0~16.fc31", rls: "FC31" ) )){
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

