if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876369" );
	script_version( "2021-09-01T11:01:35+0000" );
	script_cve_id( "CVE-2019-11596" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-01 11:01:35 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-26 16:15:00 +0000 (Tue, 26 May 2020)" );
	script_tag( name: "creation_date", value: "2019-05-17 02:12:15 +0000 (Fri, 17 May 2019)" );
	script_name( "Fedora Update for memcached FEDORA-2019-df4c0ba2db" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-df4c0ba2db" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/Y2CCWRM4LHB253KG5SPOKRVDCXQX5VZR" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'memcached'
  package(s) announced via the FEDORA-2019-df4c0ba2db advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "memcached is a high-performance, distributed memory object caching
system, generic in nature, but intended for use in speeding up dynamic
web applications by alleviating database load." );
	script_tag( name: "affected", value: "'memcached' package(s) on Fedora 29." );
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
if(release == "FC29"){
	if(!isnull( res = isrpmvuln( pkg: "memcached", rpm: "memcached~1.5.14~1.fc29", rls: "FC29" ) )){
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

