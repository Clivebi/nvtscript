if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879140" );
	script_version( "2021-08-23T12:01:00+0000" );
	script_cve_id( "CVE-2021-27645" );
	script_tag( name: "cvss_base", value: "1.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-23 12:01:00 +0000 (Mon, 23 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-06 06:15:00 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-03-20 04:07:42 +0000 (Sat, 20 Mar 2021)" );
	script_name( "Fedora: Security Advisory for glibc (FEDORA-2021-6749bfcfd9)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC34" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-6749bfcfd9" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/I7TS26LIZSOBLGJEZMJX4PXT5BQDE2WS" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'glibc'
  package(s) announced via the FEDORA-2021-6749bfcfd9 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The glibc package contains standard libraries which are used by
multiple programs on the system. In order to save disk space and
memory, as well as to make upgrading easier, common system code is
kept in one place and shared between programs. This particular package
contains the most important sets of shared libraries: the standard C
library and the standard math library. Without these two libraries, a
Linux system will not function." );
	script_tag( name: "affected", value: "'glibc' package(s) on Fedora 34." );
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
	if(!isnull( res = isrpmvuln( pkg: "glibc", rpm: "glibc~2.33~5.fc34", rls: "FC34" ) )){
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

