if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879922" );
	script_version( "2021-08-24T12:01:48+0000" );
	script_cve_id( "CVE-2021-32810" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-24 12:01:48 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-11 17:52:00 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-13 03:13:08 +0000 (Fri, 13 Aug 2021)" );
	script_name( "Fedora: Security Advisory for rust-rav1e (FEDORA-2021-a5161737c3)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC34" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-a5161737c3" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/EW5B2VTDVMJ6B3DA4VLMAMW2GGDCE2BK" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rust-rav1e'
  package(s) announced via the FEDORA-2021-a5161737c3 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Fastest and safest AV1 encoder." );
	script_tag( name: "affected", value: "'rust-rav1e' package(s) on Fedora 34." );
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
	if(!isnull( res = isrpmvuln( pkg: "rust-rav1e", rpm: "rust-rav1e~0.4.1~4.fc34", rls: "FC34" ) )){
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

