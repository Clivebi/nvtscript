if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877515" );
	script_version( "2020-02-28T12:26:57+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-02-28 12:26:57 +0000 (Fri, 28 Feb 2020)" );
	script_tag( name: "creation_date", value: "2020-02-28 04:05:48 +0000 (Fri, 28 Feb 2020)" );
	script_name( "Fedora: Security Advisory for golang-vitess (FEDORA-2020-bd764dd275)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2020-bd764dd275" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/S6LMB6HU7KB2EJKF7ZOVGUW4N6UX7EI3" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'golang-vitess'
  package(s) announced via the FEDORA-2020-bd764dd275 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Vitess is a database clustering system for horizontal scaling of MySQL through
generalized sharding.

By encapsulating shard-routing logic, Vitess allows application code and
database queries to remain agnostic to the distribution of data onto multiple
shards. With Vitess, you can even split and merge shards as your needs grow,
with an atomic cutover step that takes only a few seconds." );
	script_tag( name: "affected", value: "'golang-vitess' package(s) on Fedora 31." );
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
if(release == "FC31"){
	if(!isnull( res = isrpmvuln( pkg: "golang-vitess", rpm: "golang-vitess~3.0~4.20190701git948c251.fc31", rls: "FC31" ) )){
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

