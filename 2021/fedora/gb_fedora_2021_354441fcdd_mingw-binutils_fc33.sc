if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878894" );
	script_version( "2021-08-24T03:01:09+0000" );
	script_cve_id( "CVE-2021-20197" );
	script_tag( name: "cvss_base", value: "3.3" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-24 03:01:09 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-28 10:15:00 +0000 (Fri, 28 May 2021)" );
	script_tag( name: "creation_date", value: "2021-02-06 04:02:25 +0000 (Sat, 06 Feb 2021)" );
	script_name( "Fedora: Security Advisory for mingw-binutils (FEDORA-2021-354441fcdd)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-354441fcdd" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/KQSTKA53JTQTQPRNDZ7Q46Q2YTJZU6RV" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mingw-binutils'
  package(s) announced via the FEDORA-2021-354441fcdd advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Cross compiled binutils (utilities like &#39, strip&#39, , &#39, as&#39, , &#39, ld&#39, )
which
understand Windows executables and DLLs." );
	script_tag( name: "affected", value: "'mingw-binutils' package(s) on Fedora 33." );
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
	if(!isnull( res = isrpmvuln( pkg: "mingw-binutils", rpm: "mingw-binutils~2.34~7.fc33", rls: "FC33" ) )){
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

