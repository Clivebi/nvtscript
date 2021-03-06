if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818402" );
	script_version( "2021-09-22T05:42:45+0000" );
	script_cve_id( "CVE-2021-3781" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-22 05:42:45 +0000 (Wed, 22 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-22 01:19:18 +0000 (Wed, 22 Sep 2021)" );
	script_name( "Fedora: Security Advisory for ghostscript (FEDORA-2021-256c80b4eb)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC34" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-256c80b4eb" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/CUUU23H5AUDW3KBMY6WD4MQFZLMXYMIT" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ghostscript'
  package(s) announced via the FEDORA-2021-256c80b4eb advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This package provides useful conversion utilities based on Ghostscript software,
for converting PS, PDF and other document formats between each other.

Ghostscript is a suite of software providing an interpreter for Adobe Systems&#39,
PostScript (PS) and Portable Document Format (PDF) page description languages.
Its primary purpose includes displaying (rasterization & rendering) and printing
of document pages, as well as conversions between different document formats." );
	script_tag( name: "affected", value: "'ghostscript' package(s) on Fedora 34." );
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
if(release == "FC34"){
	if(!isnull( res = isrpmvuln( pkg: "ghostscript", rpm: "ghostscript~9.54.0~2.1.fc34", rls: "FC34" ) )){
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

