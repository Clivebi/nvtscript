if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878806" );
	script_version( "2021-08-24T03:01:09+0000" );
	script_cve_id( "CVE-2020-15216" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-24 03:01:09 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-05 13:18:00 +0000 (Wed, 05 May 2021)" );
	script_tag( name: "creation_date", value: "2021-01-14 09:51:21 +0000 (Thu, 14 Jan 2021)" );
	script_name( "Fedora: Security Advisory for golang-github-russellhaering-goxmldsig (FEDORA-2021-9316ee2948)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "FEDORA", value: "2021-9316ee2948" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/GUH33FPUXED3FHYL25BJOQPRKFGPOMS2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'golang-github-russellhaering-goxmldsig'
  package(s) announced via the FEDORA-2021-9316ee2948 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Pure Go implementation of XML Digital Signatures." );
	script_tag( name: "affected", value: "'golang-github-russellhaering-goxmldsig' package(s) on Fedora 32." );
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
	if(!isnull( res = isrpmvuln( pkg: "golang-github-russellhaering-goxmldsig", rpm: "golang-github-russellhaering-goxmldsig~1.1.0~1.fc32", rls: "FC32" ) )){
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
