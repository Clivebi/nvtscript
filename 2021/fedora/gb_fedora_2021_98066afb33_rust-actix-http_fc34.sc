if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879993" );
	script_version( "2021-08-24T12:01:48+0000" );
	script_cve_id( "CVE-2021-38512" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-24 12:01:48 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-18 15:22:00 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-23 03:21:13 +0000 (Mon, 23 Aug 2021)" );
	script_name( "Fedora: Security Advisory for rust-actix-http (FEDORA-2021-98066afb33)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC34" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-98066afb33" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/67URRW4K47SR6LNQB4YALPLGGQMQK7HO" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rust-actix-http'
  package(s) announced via the FEDORA-2021-98066afb33 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "HTTP primitives for the Actix ecosystem." );
	script_tag( name: "affected", value: "'rust-actix-http' package(s) on Fedora 34." );
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
	if(!isnull( res = isrpmvuln( pkg: "rust-actix-http", rpm: "rust-actix-http~2.2.1~1.fc34", rls: "FC34" ) )){
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

