if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877774" );
	script_version( "2021-07-14T02:00:49+0000" );
	script_cve_id( "CVE-2020-6817", "CVE-2020-6802" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-14 02:00:49 +0000 (Wed, 14 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-30 22:15:00 +0000 (Tue, 30 Mar 2021)" );
	script_tag( name: "creation_date", value: "2020-05-02 03:20:52 +0000 (Sat, 02 May 2020)" );
	script_name( "Fedora: Security Advisory for python-bleach (FEDORA-2020-e9c8bdd1e3)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "FEDORA", value: "2020-e9c8bdd1e3" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/YTULPQB7HVPPYWEYVNHJGDTSPVIDHIZX" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-bleach'
  package(s) announced via the FEDORA-2020-e9c8bdd1e3 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Bleach is an HTML sanitizing library that escapes or strips markup and
attributes based on a white list." );
	script_tag( name: "affected", value: "'python-bleach' package(s) on Fedora 32." );
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
	if(!isnull( res = isrpmvuln( pkg: "python-bleach", rpm: "python-bleach~3.1.4~2.fc32", rls: "FC32" ) )){
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

