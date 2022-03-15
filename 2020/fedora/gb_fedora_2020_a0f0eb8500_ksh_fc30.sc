if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877474" );
	script_version( "2021-07-21T11:00:56+0000" );
	script_cve_id( "CVE-2019-14868" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-07-21 11:00:56 +0000 (Wed, 21 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-09 13:46:00 +0000 (Fri, 09 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-02-16 04:03:20 +0000 (Sun, 16 Feb 2020)" );
	script_name( "Fedora: Security Advisory for ksh (FEDORA-2020-a0f0eb8500)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2020-a0f0eb8500" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/U3ITVEHF5BVMHZKST7JNOZ2ABJLBHKMT" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ksh'
  package(s) announced via the FEDORA-2020-a0f0eb8500 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "KornShell is a shell programming language, which is upward compatible
with 'sh' (the Bourne Shell)." );
	script_tag( name: "affected", value: "'ksh' package(s) on Fedora 30." );
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
	if(!isnull( res = isrpmvuln( pkg: "ksh", rpm: "ksh~2020.0.0~2.fc30", rls: "FC30" ) )){
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

