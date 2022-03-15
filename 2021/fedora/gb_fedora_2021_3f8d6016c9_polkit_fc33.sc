if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879774" );
	script_version( "2021-07-06T12:11:22+0000" );
	script_cve_id( "CVE-2021-3560" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-06 12:11:22 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-06-20 03:17:04 +0000 (Sun, 20 Jun 2021)" );
	script_name( "Fedora: Security Advisory for polkit (FEDORA-2021-3f8d6016c9)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-3f8d6016c9" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/FBORD44GPNJPRTR7EN52KG5UBJ754TAJ" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'polkit'
  package(s) announced via the FEDORA-2021-3f8d6016c9 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "polkit is a toolkit for defining and handling authorizations.  It is
used for allowing unprivileged processes to speak to privileged
processes." );
	script_tag( name: "affected", value: "'polkit' package(s) on Fedora 33." );
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
	if(!isnull( res = isrpmvuln( pkg: "polkit", rpm: "polkit~0.117~2.fc33.1", rls: "FC33" ) )){
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

