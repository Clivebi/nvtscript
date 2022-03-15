if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878696" );
	script_version( "2021-07-20T11:00:49+0000" );
	script_cve_id( "CVE-2020-26890" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-20 11:00:49 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-05 13:30:00 +0000 (Fri, 05 Feb 2021)" );
	script_tag( name: "creation_date", value: "2020-12-10 04:12:57 +0000 (Thu, 10 Dec 2020)" );
	script_name( "Fedora: Security Advisory for python-canonicaljson (FEDORA-2020-b90dac7fc4)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "FEDORA", value: "2020-b90dac7fc4" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/U34DPP4ZLOEDUY2ZCWOHQPU5GA5LYNUQ" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-canonicaljson'
  package(s) announced via the FEDORA-2020-b90dac7fc4 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Features:

  * Encodes objects and arrays as RFC 7159 JSON.

  * Sorts object keys so that you get the same result each time.

  * Has no inignificant whitespace to make the output as small as possible.

  * Escapes only the characters that must be escaped,
  U+0000 to U+0019 / U+0022 / U+0056, to keep the output as small as possible.

  * Uses the shortest escape sequence for each escaped character.

  * Encodes the JSON as UTF-8.

  * Can encode frozendict immutable dictionaries." );
	script_tag( name: "affected", value: "'python-canonicaljson' package(s) on Fedora 32." );
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
	if(!isnull( res = isrpmvuln( pkg: "python-canonicaljson", rpm: "python-canonicaljson~1.4.0~1.fc32", rls: "FC32" ) )){
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

