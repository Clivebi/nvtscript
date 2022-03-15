if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879893" );
	script_version( "2021-08-23T09:01:09+0000" );
	script_cve_id( "CVE-2021-32761" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-23 09:01:09 +0000 (Mon, 23 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-30 16:28:00 +0000 (Fri, 30 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-08-02 03:18:07 +0000 (Mon, 02 Aug 2021)" );
	script_name( "Fedora: Security Advisory for redis (FEDORA-2021-10d54c261f)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC34" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-10d54c261f" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/VGX7RRAWGXWXEAKJTQYSDSBO2BC3SAHD" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'redis'
  package(s) announced via the FEDORA-2021-10d54c261f advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Redis is an advanced key-value store. It is often referred to as a data
structure server since keys can contain strings, hashes, lists, sets and
sorted sets.

You can run atomic operations on these types, like appending to a string,
incrementing the value in a hash, pushing to a list, computing set
intersection, union and difference, or getting the member with highest
ranking in a sorted set.

In order to achieve its outstanding performance, Redis works with an
in-memory dataset. Depending on your use case, you can persist it either
by dumping the dataset to disk every once in a while, or by appending
each command to a log.

Redis also supports trivial-to-setup master-slave replication, with very
fast non-blocking first synchronization, auto-reconnection on net split
and so forth.

Other features include Transactions, Pub/Sub, Lua scripting, Keys with a
limited time-to-live, and configuration settings to make Redis behave like
a cache.

You can use Redis from most programming languages also." );
	script_tag( name: "affected", value: "'redis' package(s) on Fedora 34." );
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
	if(!isnull( res = isrpmvuln( pkg: "redis", rpm: "redis~6.2.5~1.fc34", rls: "FC34" ) )){
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

